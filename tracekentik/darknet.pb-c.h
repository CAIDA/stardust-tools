/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: darknet.proto */

#ifndef PROTOBUF_C_darknet_2eproto__INCLUDED
#define PROTOBUF_C_darknet_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1002001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _Darknet__DarknetFlow Darknet__DarknetFlow;
typedef struct _Darknet__DarknetFlows Darknet__DarknetFlows;


/* --- enums --- */


/* --- messages --- */

struct  _Darknet__DarknetFlow
{
  ProtobufCMessage base;
  protobuf_c_boolean has_timestamp;
  uint64_t timestamp;
  protobuf_c_boolean has_in_bytes;
  uint64_t in_bytes;
  protobuf_c_boolean has_in_pkts;
  uint64_t in_pkts;
  protobuf_c_boolean has_input_port;
  uint32_t input_port;
  protobuf_c_boolean has_ipv4_dst_addr;
  uint32_t ipv4_dst_addr;
  protobuf_c_boolean has_ipv4_src_addr;
  uint32_t ipv4_src_addr;
  protobuf_c_boolean has_l4_dst_port;
  uint32_t l4_dst_port;
  protobuf_c_boolean has_l4_src_port;
  uint32_t l4_src_port;
  protobuf_c_boolean has_output_port;
  uint32_t output_port;
  protobuf_c_boolean has_protocol;
  uint32_t protocol;
  protobuf_c_boolean has_tcp_flags;
  uint32_t tcp_flags;
  protobuf_c_boolean has_vlan_in;
  uint32_t vlan_in;
  protobuf_c_boolean has_vlan_out;
  uint32_t vlan_out;
  protobuf_c_boolean has_sample_rate;
  uint32_t sample_rate;
  protobuf_c_boolean has_packet_id;
  uint64_t packet_id;
  protobuf_c_boolean has_device_id;
  uint32_t device_id;
};
#define DARKNET__DARKNET_FLOW__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&darknet__darknet_flow__descriptor) \
    , 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0 }


struct  _Darknet__DarknetFlows
{
  ProtobufCMessage base;
  size_t n_flow;
  Darknet__DarknetFlow **flow;
};
#define DARKNET__DARKNET_FLOWS__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&darknet__darknet_flows__descriptor) \
    , 0,NULL }


/* Darknet__DarknetFlow methods */
void   darknet__darknet_flow__init
                     (Darknet__DarknetFlow         *message);
size_t darknet__darknet_flow__get_packed_size
                     (const Darknet__DarknetFlow   *message);
size_t darknet__darknet_flow__pack
                     (const Darknet__DarknetFlow   *message,
                      uint8_t             *out);
size_t darknet__darknet_flow__pack_to_buffer
                     (const Darknet__DarknetFlow   *message,
                      ProtobufCBuffer     *buffer);
Darknet__DarknetFlow *
       darknet__darknet_flow__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   darknet__darknet_flow__free_unpacked
                     (Darknet__DarknetFlow *message,
                      ProtobufCAllocator *allocator);
/* Darknet__DarknetFlows methods */
void   darknet__darknet_flows__init
                     (Darknet__DarknetFlows         *message);
size_t darknet__darknet_flows__get_packed_size
                     (const Darknet__DarknetFlows   *message);
size_t darknet__darknet_flows__pack
                     (const Darknet__DarknetFlows   *message,
                      uint8_t             *out);
size_t darknet__darknet_flows__pack_to_buffer
                     (const Darknet__DarknetFlows   *message,
                      ProtobufCBuffer     *buffer);
Darknet__DarknetFlows *
       darknet__darknet_flows__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   darknet__darknet_flows__free_unpacked
                     (Darknet__DarknetFlows *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Darknet__DarknetFlow_Closure)
                 (const Darknet__DarknetFlow *message,
                  void *closure_data);
typedef void (*Darknet__DarknetFlows_Closure)
                 (const Darknet__DarknetFlows *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor darknet__darknet_flow__descriptor;
extern const ProtobufCMessageDescriptor darknet__darknet_flows__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_darknet_2eproto__INCLUDED */
