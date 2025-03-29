/* meshtastic.c
 *
 * SPDX-FileCopyrightText: © 2025 Antonio Vázquez Blanco
 * <antoniovazquezblanco@gmail.com> SPDX-FileCopyrightText: © 2025 Kevin Leon
 * <kevinleon.morales@gmail.com> SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include <epan/packet.h>
#include <epan/uat.h>
#include <glib.h>
#include <wiretap/wtap.h>
#include <wsutil/wsgcrypt.h>

#define MESHTASTIC_ADDR_LEN 4
#define MESHTASTIC_PKTID_LEN 4
#define MESHTASTIC_CIPHER_BLOCK_LEN 16

// Common define
#define MESHTASTIC_BCAST_ALL 0xFFFFFF

static int dissect_meshtastic_payload(tvbuff_t* tvb,
                                      packet_info* pinfo,
                                      proto_tree* tree,
                                      void* data _U_);

// Default 1 byte key
static const uint8_t psk_key[] = {0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29,
                                  0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab,
                                  0xcf, 0x4e, 0x69, 0x01};

// Dissector handles
static dissector_handle_t handle_meshtastic;
static dissector_handle_t meshtastic_payload_handle;
// Protocol handles
static int proto_meshtastic;

// Header field handles
static int hf_meshtastic_dst;
static int hf_meshtastic_src;
static int hf_meshtastic_pktid;
static int hf_meshtastic_flags;
static int hf_meshtastic_flags_hop_limit;
static int hf_meshtastic_flags_want_ack;
static int hf_meshtastic_flags_via_mqtt;
static int hf_meshtastic_flags_hop_start;
static int hf_meshtastic_channelhash;
static int hf_meshtastic_nexthop;
static int hf_meshtastic_relaynode;
static int hf_meshtastic_payload;
static int hf_meshtastic_decrypted_block;

// Meshtastic Packets types
static int hf_mstic_type_packet;
static int hf_mstic_bitfield;
// Portnum 1 - Text Message
static int hf_mstic_textapp_message_len;
static int hf_mstic_textapp_message;
// Portnum 3 - Position
// static int hf_mstic_position_latitude;
// Portnum 67 - Telemetry
// TELEMETRY_APP time: 1742950869
// device_metrics {
//   battery_level: 101
//   voltage: -0.001
//   channel_utilization: 0.27
//   air_util_tx: 0.00450000027
//   uptime_seconds: 45
// }
//  battery_level: 101
// voltage: -0.001
// channel_utilization: 0.27
// air_util_tx: 0.00450000027
// uptime_seconds: 45

// static int hf_mstic_telemetry_time;
// static int hf_mstic_telemetry_dev_battery;
// static int hf_mstic_telemetry_dev_voltage;
// static int hf_mstic_telemetry_dev_channel;
// static int hf_mstic_telemetry_dev_air;

// Subtree pointers
static int ett_header;
static int ett_flags;
static int ett_cipher_block;

// Meshtastic key type
typedef enum {
  KEY_SIZE_NONE = 0x00,
  KEY_SIZE_1BYTE = 0x01,
  KEY_SIZE_128BITS = 0x02,
  KEY_SIZE_256BITS = 0x03,
} meshtastic_key_sizes_type;

/**
 * If we have a channel name, we can relationate the key and channel
 * So, when the packet is dissected, we can select which key to use
 */
typedef struct {
  char* key_channel_name;
  char* key_base64;
  meshtastic_key_sizes_type key_size;
} meshtastic_key_t;

/* Enumeration for key size decryption */
static const value_string meshtastic_key_size[] = {
    {KEY_SIZE_NONE, "No key"},
    {KEY_SIZE_1BYTE, "1 Byte"},
    {KEY_SIZE_128BITS, "128 bits"},
    {KEY_SIZE_256BITS, "256 bits"},
    {0, NULL}};

static const value_string meshtastic_portnum[] = {{0, "Unknown"},
                                                  {1, "Text Message"},
                                                  {2, "Remote Hardware"},
                                                  {3, "Position App"},
                                                  {0, NULL}};

// Preferences
static uat_t* uat_keys;
static meshtastic_key_t* uat_meshtastic_keys;
static unsigned uat_meshtastic_keys_num;

UAT_CSTRING_CB_DEF(uat_meshtastic_keys_list, key_channel_name, meshtastic_key_t)
UAT_CSTRING_CB_DEF(uat_meshtastic_keys_list, key_base64, meshtastic_key_t)
UAT_VS_DEF(uat_meshtastic_keys_list,
           key_size,
           meshtastic_key_t,
           meshtastic_key_sizes_type,
           KEY_SIZE_1BYTE,
           "1 Byte")

bool uat_meshtastic_keys_fld_name_cb(void* r _U_,
                                     const char* p,
                                     unsigned len _U_,
                                     const void* u1 _U_,
                                     const void* u2 _U_,
                                     char** err) {
  if (!p || strlen(p) == 0u) {
    // TODO: Can the name be empty?
    *err = NULL;
    return true;
  }

  *err = NULL;
  return true;
}

bool uat_meshtastic_keys_fld_key_cb(void* r _U_,
                                    const char* p,
                                    unsigned len _U_,
                                    const void* u1 _U_,
                                    const void* u2 _U_,
                                    char** err) {
  meshtastic_key_t* rec = (meshtastic_key_t*)r;

  if (rec != KEY_SIZE_NONE && (!p || strlen(p) == 0u)) {
    *err = g_strdup("Key cannot be empty.");
    return false;
  }

  /* Validate Base64 key */
  size_t key_len;
  char* data = g_base64_decode(rec->key_base64, &key_len);
  if (key_len == 0) {
    *err = g_strdup("Base64 format error.");
    free(data);
    return false;
  }
  // TODO: Relation between key_size and decrypted data len
  *err = NULL;
  return true;
}

static void uat_meshtastic_keys_free_cb(void* r) {
  meshtastic_key_t* h = (meshtastic_key_t*)r;
  g_free(h->key_channel_name);
  g_free(h->key_base64);
}

static void* uat_meshtastic_keys_copy_cb(void* dest,
                                         const void* orig,
                                         size_t len _U_) {
  const meshtastic_key_t* o = (const meshtastic_key_t*)orig;
  meshtastic_key_t* d = (meshtastic_key_t*)dest;

  d->key_channel_name = g_strdup(o->key_channel_name);
  d->key_base64 = g_strdup(o->key_base64);
  d->key_size = o->key_size;
  return d;
}

/* Forward declaration needed for preference registration */
void proto_reg_handoff_meshtastic(void);

/**
 * Cipher block
 * We need a nonce:
 * packetid + 0x00\0x00\0x00\0x00\ + sender + 0x00\0x00\0x00\0x00
 * Then use the default key to decrypt the payload. TODO: Add key input
 */
static int meshtastic_decrypt_aes_crt(uint8_t* cipher_block,
                                      uint16_t cipher_len,
                                      uint32_t packetID,
                                      uint32_t senderID) {
  uint8_t iv[MESHTASTIC_CIPHER_BLOCK_LEN];  // Nonce
  memset(iv, 0, MESHTASTIC_CIPHER_BLOCK_LEN);
  memcpy(iv, &packetID, sizeof(packetID));
  memcpy(iv + MESHTASTIC_ADDR_LEN + MESHTASTIC_ADDR_LEN, &senderID,
         sizeof(senderID));

  gcry_cipher_hd_t cipher_hd;
  if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR,
                       0)) {
    return -1;
  }

  if (gcry_cipher_setkey(cipher_hd, psk_key, MESHTASTIC_CIPHER_BLOCK_LEN)) {
    gcry_cipher_close(cipher_hd);
    return -2;
  }

  if (gcry_cipher_setctr(cipher_hd, iv, MESHTASTIC_CIPHER_BLOCK_LEN)) {
    gcry_cipher_close(cipher_hd);
    return -3;
  }

  if (gcry_cipher_decrypt(cipher_hd, cipher_block, cipher_len, NULL, 0)) {
    gcry_cipher_close(cipher_hd);
    return -4;
  }

  gcry_cipher_close(cipher_hd);
  return 0;
}

static int dissect_textmessage_info(tvbuff_t* tvb,
                                    packet_info* pinfo,
                                    proto_tree* tree,
                                    uint16_t offset) {
  (void)pinfo;
  offset += 1;  // Still not enumerated
  offset += 1;  // Still not enumerated
  uint8_t text_len = tvb_get_uint8(tvb, offset);
  proto_tree_add_item(tree, hf_mstic_textapp_message_len, tvb, offset, 1,
                      ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_mstic_textapp_message, tvb, offset, text_len,
                      ENC_NA);
  offset += 1;
  return offset;
}

static int dissect_meshtastic_payload(tvbuff_t* tvb,
                                      packet_info* pinfo,
                                      proto_tree* tree,
                                      void* data _U_) {
  uint16_t offset = 0;
  // Bitfield
  proto_tree_add_item(tree, hf_mstic_bitfield, tvb, offset, 1, ENC_NA);
  offset += 1;
  // Portnum
  uint8_t portnum = tvb_get_uint8(tvb, offset);
  proto_tree_add_item(tree, hf_mstic_type_packet, tvb, offset, 1, portnum);
  col_set_str(
      pinfo->cinfo, COL_INFO,
      val_to_str_const(portnum, meshtastic_portnum, "Not supported yet"));

  switch (portnum) {
    case 1:
      offset = dissect_textmessage_info(tvb, pinfo, tree, offset);
      break;
    default:
      break;
  }

  return offset;
}

static int dissect_meshtastic(tvbuff_t* tvb,
                              packet_info* pinfo,
                              proto_tree* tree,
                              void* data) {
  // For -Werro unused
  (void)data;
  int32_t current_offset = 0;

  // Set columns
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Meshtastic");
  col_clear(pinfo->cinfo, COL_INFO);
  col_clear(pinfo->cinfo, COL_DEF_DST);
  col_clear(pinfo->cinfo, COL_DEF_SRC);

  // Create subtrees
  proto_item* ti =
      proto_tree_add_item(tree, proto_meshtastic, tvb, 0, -1, ENC_NA);
  proto_tree* ti_radio = proto_item_add_subtree(ti, ett_header);

  // Destination address
  guint32 dst_addr = GUINT32_SWAP_LE_BE(tvb_get_ntohl(tvb, current_offset));
  proto_tree_add_uint(ti_radio, hf_meshtastic_dst, tvb, current_offset,
                      MESHTASTIC_ADDR_LEN, dst_addr);
  col_add_fstr(pinfo->cinfo, COL_DEF_DST, "%08x", dst_addr);
  current_offset += MESHTASTIC_ADDR_LEN;

  // Source address
  guint32 src_addr = GUINT32_SWAP_LE_BE(tvb_get_ntohl(tvb, current_offset));
  uint32_t senderID = tvb_get_letohl(tvb, current_offset);
  proto_tree_add_uint(ti_radio, hf_meshtastic_src, tvb, current_offset,
                      MESHTASTIC_ADDR_LEN, src_addr);
  col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "%08x", src_addr);
  current_offset += MESHTASTIC_ADDR_LEN;

  // Packet ID
  guint32 packetid = GUINT32_SWAP_LE_BE(tvb_get_ntohl(tvb, current_offset));
  uint32_t packetID = tvb_get_letohl(tvb, current_offset);
  proto_tree_add_uint(ti_radio, hf_meshtastic_pktid, tvb, current_offset,
                      MESHTASTIC_PKTID_LEN, packetid);
  current_offset += MESHTASTIC_PKTID_LEN;

  // Flags
  uint8_t flags_value = tvb_get_uint8(tvb, current_offset);
  proto_item* ti_flags = proto_tree_add_uint_format(
      ti_radio, hf_meshtastic_flags, tvb, current_offset, 1, flags_value,
      "Flags: 0x%02x", flags_value);
  proto_tree* field_tree = proto_item_add_subtree(ti_flags, ett_flags);
  proto_tree_add_uint(field_tree, hf_meshtastic_flags_hop_limit, tvb,
                      current_offset, 1, flags_value & 0b111);
  proto_tree_add_boolean(field_tree, hf_meshtastic_flags_want_ack, tvb,
                         current_offset, 1, (flags_value >> 3) & 0b1);
  proto_tree_add_boolean(field_tree, hf_meshtastic_flags_via_mqtt, tvb,
                         current_offset, 1, (flags_value >> 4) & 0b1);
  proto_tree_add_uint(field_tree, hf_meshtastic_flags_hop_start, tvb,
                      current_offset, 1, (flags_value >> 5) & 0b111);
  current_offset += 1;

  uint8_t channel_hash = tvb_get_uint8(tvb, current_offset);
  proto_tree_add_uint(ti_radio, hf_meshtastic_channelhash, tvb, current_offset,
                      1, channel_hash);
  current_offset += 1;

  // Next hop
  proto_tree_add_item(ti_radio, hf_meshtastic_nexthop, tvb, current_offset, 1,
                      ENC_NA);
  current_offset += 1;

  // Relay node
  proto_tree_add_item(ti_radio, hf_meshtastic_relaynode, tvb, current_offset, 1,
                      ENC_NA);
  current_offset += 1;

  // Payload
  uint16_t payload_len = tvb_captured_length_remaining(tvb, current_offset);
  proto_item* payload_block =
      proto_tree_add_item(ti_radio, hf_meshtastic_payload, tvb, current_offset,
                          payload_len, ENC_NA);

  // Channel hash
  /* This creapy value can change, if the channel hash are named as PwnChannel
   * The result are 0x08 meaning that xorHash are LongFast
   * So...IDK how to handle this information in the dissector
   * For now if the channel_hash value are 0x00 meaning in the protocol
   * haven't encryption so return and don't cipher
   */
  // If channel hash are 0x75 means that is unencrypted packet
  // So we just only dissect the data
  uint8_t* payload_data =
      tvb_memdup(pinfo->pool, tvb, current_offset, payload_len);
  if (channel_hash == 0x75) {
    tvbuff_t* tvb_payload =
        tvb_new_child_real_data(tvb, payload_data, payload_len, payload_len);
    call_dissector(meshtastic_payload_handle, tvb_payload, pinfo,
                   payload_block);
    return 0;
  }

  // We copy the a new cipher block for decrypt
  uint8_t* payload_data =
      tvb_memdup(pinfo->pool, tvb, current_offset, payload_len);

  int err =
      meshtastic_decrypt_aes_crt(payload_data, payload_len, packetID, senderID);
  if (err != 0) {
    col_set_str(pinfo->cinfo, COL_INFO, "[Failed cipher decrypt]");
    return tvb_captured_length(tvb);
  }

  tvbuff_t* tvb_decrypted =
      tvb_new_child_real_data(tvb, payload_data, payload_len, payload_len);
  tvb_decrypted =
      tvb_new_subset_length_caplen(tvb_decrypted, 0, payload_len, payload_len);

  proto_item* pi_decrypted =
      proto_tree_add_item(ti_radio, hf_meshtastic_decrypted_block,
                          tvb_decrypted, 0, payload_len, ENC_NA);
  add_new_data_source(pinfo, tvb_decrypted, "Decrypted Meshtastic Packet");
  proto_tree* subtree_decrypted =
      proto_item_add_subtree(pi_decrypted, ett_cipher_block);

  //  We decrypt the data so we can use the dissector
  call_dissector(meshtastic_payload_handle, tvb_decrypted, pinfo,
                 subtree_decrypted);
  return 0;
}

void proto_register_meshtastic(void) {
  // Setup a list of header fields
  static hf_register_info hf[] = {
      {&hf_meshtastic_dst,
       {"Destination", "meshtastic.dst", FT_UINT32, BASE_HEX, NULL, 0x0,
        "Destination Address", HFILL}},
      {&hf_meshtastic_src,
       {"Source", "meshtastic.src", FT_UINT32, BASE_HEX, NULL, 0x0,
        "Source Address", HFILL}},
      {&hf_meshtastic_pktid,
       {"Packet ID", "meshtastic.pktid", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_meshtastic_flags,
       {"Flags", "meshtastic.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_meshtastic_flags_hop_limit,
       {"Hop Limit", "meshtastic.hop_limit", FT_UINT8, BASE_DEC, NULL, 0x07,
        NULL, HFILL}},
      {&hf_meshtastic_flags_want_ack,
       {"Want Ack", "meshtastic.want_ack", FT_BOOLEAN, 8, NULL, 0x08, NULL,
        HFILL}},
      {&hf_meshtastic_flags_via_mqtt,
       {"Via MQTT", "meshtastic.via_mqtt", FT_BOOLEAN, 8, NULL, 0x10, NULL,
        HFILL}},
      {&hf_meshtastic_flags_hop_start,
       {"Hop Start", "meshtastic.hop_start", FT_UINT8, BASE_DEC, NULL, 0xE0,
        NULL, HFILL}},
      {&hf_meshtastic_channelhash,
       {"Channel Hash", "meshtastic.channelhash", FT_UINT8, BASE_DEC_HEX, NULL,
        0x0, NULL, HFILL}},
      {&hf_meshtastic_nexthop,
       {"Next Hop", "meshtastic.nexthop", FT_UINT8, BASE_DEC, NULL, 0x0, NULL,
        HFILL}},
      {&hf_meshtastic_relaynode,
       {"Relay Node", "meshtastic.relaynode", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
      {&hf_meshtastic_payload,
       {"Payload", "meshtastic.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
        HFILL}},
      {&hf_meshtastic_decrypted_block,
       {"Decrypted", "meshtastic.decryp_block", FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
      {&hf_mstic_type_packet,
       {"Portnum", "meshtastic.portnum", FT_UINT8, BASE_DEC,
        VALS(meshtastic_portnum), 0, NULL, HFILL}},
      {&hf_mstic_bitfield,
       {"Bitfield", "meshtastic.bitfield", FT_UINT8, BASE_DEC, NULL, 0x0, NULL,
        HFILL}}};

  static hf_register_info hf_app_text_message[] = {
      {&hf_mstic_textapp_message_len,
       {"Length", "meshtastic.textapp_message_len", FT_UINT8, BASE_DEC, NULL,
        0x0, NULL, HFILL}},
      {&hf_mstic_textapp_message,
       {"Message", "meshtastic.textapp_message", FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
  };

  // Protocol subtrees array
  static int* ett[] = {
      &ett_header,
      &ett_flags,
      &ett_cipher_block,
  };

  // Register protocol
  proto_meshtastic =
      proto_register_protocol("Meshtastic", "Meshtastic", "meshtastic");

  // Register dissectors
  handle_meshtastic =
      register_dissector("meshtastic", dissect_meshtastic, proto_meshtastic);

  // Register header fields
  proto_register_field_array(proto_meshtastic, hf, array_length(hf));
  proto_register_field_array(proto_meshtastic, hf_app_text_message,
                             array_length(hf_app_text_message));

  // Register subtrees
  proto_register_subtree_array(ett, array_length(ett));
  // Register preferences
  module_t* meshtastic_module =
      prefs_register_protocol(proto_meshtastic, proto_reg_handoff_meshtastic);

  static uat_field_t uat_meshtastic_key_flds[] = {
      UAT_FLD_CSTRING_OTHER(uat_meshtastic_keys_list, key_channel_name,
                            "Key name", uat_meshtastic_keys_fld_name_cb,
                            "Key name."),
      UAT_FLD_CSTRING_OTHER(uat_meshtastic_keys_list, key_base64, "Base64 key",
                            uat_meshtastic_keys_fld_key_cb,
                            "Key in base64 format."),
      UAT_FLD_VS(uat_meshtastic_keys_list, key_size, "Size",
                 meshtastic_key_size, "Size of the key."),
      UAT_END_FIELDS};

  uat_keys =
      uat_new("Meshtastic Decrypt", sizeof(meshtastic_key_t),
              "meshtastic_keys",        /* filename */
              true,                     /* from_profile */
              &uat_meshtastic_keys,     /* data_ptr */
              &uat_meshtastic_keys_num, /* numitems_ptr */
              UAT_AFFECTS_DISSECTION, /* affects dissection of packets, but not
                                         set of named fields */
              NULL,                   /* Help section (currently a wiki page) */
              uat_meshtastic_keys_copy_cb, NULL, uat_meshtastic_keys_free_cb,
              NULL,  // ssl_parse_uat,
              NULL,  // ssl_reset_uat,
              uat_meshtastic_key_flds);

  prefs_register_uat_preference(
      meshtastic_module, "key_table", "Meshtastic keys list",
      "A table of Meshtastic keys for decryption", uat_keys);
}

void proto_reg_handoff_meshtastic(void) {
  meshtastic_payload_handle =
      create_dissector_handle(dissect_meshtastic_payload, proto_meshtastic);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_USER1, handle_meshtastic);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_USER1, meshtastic_payload_handle);
}