#include "router.hh"

#include <iostream>
#include <limits>

using namespace std;

// route_prefix: The "up-to-32-bit" IPv4 address prefix to match the datagram's destination address against
// prefix_length: For this route to be applicable, how many high-order (most-significant) bits of
//    the route_prefix will need to match the corresponding bits of the datagram's destination address?
// next_hop: The IP address of the next hop. Will be empty if the network is directly attached to the router (in
//    which case, the next hop address should be the datagram's final destination).
// interface_num: The index of the interface to send the datagram out on.
void Router::add_route( const uint32_t route_prefix,
                        const uint8_t prefix_length,
                        const optional<Address> next_hop,
                        const size_t interface_num )
{
  cerr << "DEBUG: adding route " << Address::from_ipv4_numeric( route_prefix ).ip() << "/"
       << static_cast<int>( prefix_length ) << " => " << ( next_hop.has_value() ? next_hop->ip() : "(direct)" )
       << " on interface " << interface_num << "\n";

  forward_table.push_back({route_prefix, prefix_length, next_hop, interface_num});
}

void Router::route() {
  for (auto &interface: interfaces_) {
        while (true) {
            auto temp = interface.maybe_receive();
            if (!temp.has_value())
                break;
            auto datagram = *temp;
            // checking ttl
            if (datagram.header.ttl == 0 || --datagram.header.ttl == 0)
                continue;
            datagram.header.compute_checksum();

            int idx = -1;
            uint8_t len;
            uint64_t curr, dest;
            // loop thru routing table
            for (size_t i = 0; i < forward_table.size(); i++) {
                auto route = forward_table[i];
                len = 32 - route.prefix_length;
                curr = uint64_t(route.route_prefix) >> len;
                dest = uint64_t(datagram.header.dst) >> len;
                // find matching address route
                if (curr == dest) {
                    // find route with longest prefix
                    if (idx == -1 || forward_table[idx].prefix_length < route.prefix_length)
                        idx = i;
                }
            }
            // route not found
            if (idx == -1)
                continue;

            // found route
            auto next_hop = forward_table[idx].next_hop;
            auto int_idx = size_t(forward_table[idx].interface_num);
            if (next_hop.has_value())
                this->interface(int_idx).send_datagram(datagram, next_hop.value());
            else // destination is reached
                this->interface(int_idx)
                        .send_datagram(datagram, Address::from_ipv4_numeric(datagram.header.dst));
        }
  }
}
