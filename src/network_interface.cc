#include "network_interface.hh"

#include "arp_message.hh"
#include "ethernet_frame.hh"

using namespace std;

// ethernet_address: Ethernet (what ARP calls "hardware") address of the interface
// ip_address: IP (what ARP calls "protocol") address of the interface
NetworkInterface::NetworkInterface( const EthernetAddress& ethernet_address, const Address& ip_address )
  : ethernet_address_( ethernet_address ), ip_address_( ip_address )
{
  cerr << "DEBUG: Network interface has Ethernet address " << to_string( ethernet_address_ ) << " and IP address "
       << ip_address.ip() << "\n";
}

// dgram: the IPv4 datagram to be sent
// next_hop: the IP address of the interface to send it to (typically a router or default gateway, but
// may also be another host if directly connected to the same network as the destination)

// Note: the Address type can be converted to a uint32_t (raw 32-bit IP address) by using the
// Address::ipv4_numeric() method.
void NetworkInterface::send_datagram( const InternetDatagram& dgram, const Address& next_hop )
{
  uint32_t next_hop_ip = next_hop.ipv4_numeric();
  EthernetFrame frame;
  EthernetHeader header;
  Serializer serializer;

  // if MAC address is known, send the datagram
  if (ARP_table.count(next_hop_ip)){
    header.type = EthernetHeader::TYPE_IPv4;
    header.src = ethernet_address_;
    header.dst = ARP_table[next_hop_ip].mac_addr;
    frame.header = header;

    dgram.serialize(serializer);
    frame.payload = serializer.output();
    ready_queue.push(frame);
  
  // unknown, broadcast ARP request if last request is more than 5s ago
  }else{
    if (!last_ARP_time.count(next_hop_ip)){
      header.type = EthernetHeader::TYPE_ARP;
      header.src = ethernet_address_;
      header.dst = ETHERNET_BROADCAST;
      frame.header = header;

      // construct an ARP request
      ARPMessage request;
      request.opcode = ARPMessage::OPCODE_REQUEST;
      request.sender_ip_address = ip_address_.ipv4_numeric();
      request.sender_ethernet_address = ethernet_address_;
      request.target_ip_address = next_hop_ip;
      request.serialize(serializer);
      frame.payload = serializer.output();
      ready_queue.push(frame);
      
      // update last ARP request time
      last_ARP_time[next_hop_ip] = curr_time;
    }
    // add datagram to the queue that holds previous packets that are waiting for dst MAC address
    wait_mac_queue[next_hop_ip].push(dgram);
  }
}

// frame: the incoming Ethernet frame
optional<InternetDatagram> NetworkInterface::recv_frame( const EthernetFrame& frame )
{
  if (frame.header.dst != ETHERNET_BROADCAST && frame.header.dst != ethernet_address_)
    return {};

  // receiving a datagram
  if (frame.header.type == EthernetHeader::TYPE_IPv4){
    InternetDatagram data;
    if (!parse(data, frame.payload)) return {};
    return data;

  // receiving an ARP message
  } else if (frame.header.type == EthernetHeader::TYPE_ARP){
    ARPMessage message;
    if (!parse(message, frame.payload)) return {};

    // cache sender MAC address
    MacAddress mac_addr;
    mac_addr.cache_time = curr_time;
    mac_addr.mac_addr = message.sender_ethernet_address;
    ARP_table[message.sender_ip_address] = mac_addr;

    // this message is a request asking for this network's MAC address, reply ARP message
    if (message.opcode == ARPMessage::OPCODE_REQUEST && message.target_ip_address == ip_address_.ipv4_numeric()){
        ARPMessage reply;
        EthernetFrame send_frame;
        EthernetHeader header;
        Serializer serializer;

        header.type = EthernetHeader::TYPE_ARP;
        header.src = ethernet_address_;
        header.dst = message.sender_ethernet_address;
        send_frame.header = header;

        reply.opcode = ARPMessage::OPCODE_REPLY;
        reply.sender_ethernet_address = ethernet_address_;
        reply.sender_ip_address = ip_address_.ipv4_numeric();
        reply.target_ethernet_address = message.sender_ethernet_address;
        reply.target_ip_address = message.sender_ip_address;
        reply.serialize(serializer);

        send_frame.payload = serializer.output();
        ready_queue.push(send_frame);
    }
    
    // if there's datagram waiting in queue to be sent to this sender,
    // send the datagram, since the MAC address is now known
    if (wait_mac_queue.count(message.sender_ip_address)){
      auto &queue = wait_mac_queue[message.sender_ip_address];
      while (queue.size()){
        EthernetFrame send_frame;
        EthernetHeader header;
        Serializer serializer;

        header.type = EthernetHeader::TYPE_IPv4;
        header.src = ethernet_address_;
        header.dst = message.sender_ethernet_address;
        send_frame.header = header;

        InternetDatagram data = queue.front();
        queue.pop();
        data.serialize(serializer);

        send_frame.payload = serializer.output();
        ready_queue.push(send_frame);
      }

      if (last_ARP_time.count(message.sender_ip_address))
        last_ARP_time.erase(message.sender_ip_address);
    }
  }

  return {};
}

// ms_since_last_tick: the number of milliseconds since the last call to this method
void NetworkInterface::tick( const size_t ms_since_last_tick )
{
  curr_time += ms_since_last_tick;

  for(auto i = ARP_table.begin(); i != ARP_table.end();){
    if (curr_time - i->second.cache_time >= 30 * 1000){
      i = ARP_table.erase(i);
    }else{
      ++i;
    }
  }

  for(auto j = last_ARP_time.begin(); j != last_ARP_time.end();){
    if (curr_time - j->second >= 5 * 1000){
      j = last_ARP_time.erase(j);
    }else{
      ++j;
    }
  }
}

optional<EthernetFrame> NetworkInterface::maybe_send()
{
  if (ready_queue.size()) {
      auto frame = ready_queue.front();
      ready_queue.pop();
      return frame;
  }
  return {};
}
