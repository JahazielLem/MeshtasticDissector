/* meshtastic.c
 *
 * SPDX-FileCopyrightText: © 2025 Antonio Vázquez Blanco
 * <antoniovazquezblanco@gmail.com> SPDX-FileCopyrightText: © 2025 Kevin Leon
 * <kevinleon.morales@gmail.com> SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include <epan/packet.h>
#include <epan/uat.h>
#include <wiretap/wtap.h>

#define MESHTASTIC_ADDR_LEN 4
#define MESHTASTIC_PKTID_LEN 4

// Dissector handles
static dissector_handle_t handle_meshtastic;

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

// Subtree pointers
static int ett_header;
static int ett_flags;

// Meshtastic key type
typedef struct {
  char* key_name;
  char* key_base64;
} meshtastic_key_t;

// Preferences
static uat_t* uat_keys;
static meshtastic_key_t* uat_meshtastic_keys;
static unsigned uat_meshtastic_keys_num;

UAT_CSTRING_CB_DEF(uat_meshtastic_keys_list, key_name, meshtastic_key_t)
UAT_CSTRING_CB_DEF(uat_meshtastic_keys_list, key_base64, meshtastic_key_t)

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
  if (!p || strlen(p) == 0u) {
    *err = g_strdup("Key cannot be empty.");
    return false;
  }

  // TODO: Check base64 format.

  *err = NULL;
  return true;
}

static void uat_meshtastic_keys_free_cb(void* r) {
  meshtastic_key_t* h = (meshtastic_key_t*)r;
  g_free(h->key_name);
  g_free(h->key_base64);
}

static void* uat_meshtastic_keys_copy_cb(void* dest,
                                         const void* orig,
                                         size_t len _U_) {
  const meshtastic_key_t* o = (const meshtastic_key_t*)orig;
  meshtastic_key_t* d = (meshtastic_key_t*)dest;

  d->key_name = g_strdup(o->key_name);
  d->key_base64 = g_strdup(o->key_base64);

  return d;
}

/* Forward declaration needed for preference registration */
void proto_reg_handoff_meshtastic(void);

static int dissect_meshtastic(tvbuff_t* tvb,
                              packet_info* pinfo,
                              proto_tree* tree,
                              void* data) {
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
  proto_tree_add_uint(ti_radio, hf_meshtastic_src, tvb, current_offset,
                      MESHTASTIC_ADDR_LEN, src_addr);
  col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "%08x", src_addr);
  current_offset += MESHTASTIC_ADDR_LEN;

  // Packet ID
  guint32 packetid = GUINT32_SWAP_LE_BE(tvb_get_ntohl(tvb, current_offset));
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

  // Channel hash
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
  proto_tree_add_item(ti_radio, hf_meshtastic_payload, tvb, current_offset,
                      payload_len, ENC_NA);

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
  };

  // Protocol subtrees array
  static int* ett[] = {
      &ett_header,
      &ett_flags,
  };

  // Register protocol
  proto_meshtastic =
      proto_register_protocol("Meshtastic", "Meshtastic", "meshtastic");

  // Register dissectors
  handle_meshtastic =
      register_dissector("meshtastic", dissect_meshtastic, proto_meshtastic);

  // Register header fields
  proto_register_field_array(proto_meshtastic, hf, array_length(hf));

  // Register subtrees
  proto_register_subtree_array(ett, array_length(ett));

  // Register preferences
  module_t* meshtastic_module =
      prefs_register_protocol(proto_meshtastic, proto_reg_handoff_meshtastic);

  static uat_field_t uat_meshtastic_key_flds[] = {
      UAT_FLD_CSTRING_OTHER(uat_meshtastic_keys_list, key_name, "Key name",
                            uat_meshtastic_keys_fld_name_cb, "Key name"),
      UAT_FLD_CSTRING_OTHER(uat_meshtastic_keys_list, key_base64, "Base64 key",
                            uat_meshtastic_keys_fld_key_cb,
                            "Key in base64 format"),
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
  dissector_add_uint("wtap_encap", WTAP_ENCAP_USER1, handle_meshtastic);
}
