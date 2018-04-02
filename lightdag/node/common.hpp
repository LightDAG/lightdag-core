#pragma once

#include <lightdag/common.hpp>
#include <lightdag/lib/interface.h>

#include <boost/asio.hpp>

#include <bitset>

#include <xxhash/xxhash.h>

namespace lightdag
{
using endpoint = boost::asio::ip::udp::endpoint;
bool parse_port (std::string const &, uint16_t &);
bool parse_address_port (std::string const &, boost::asio::ip::address &, uint16_t &);
using tcp_endpoint = boost::asio::ip::tcp::endpoint;
bool parse_endpoint (std::string const &, lightdag::endpoint &);
bool parse_tcp_endpoint (std::string const &, lightdag::tcp_endpoint &);
bool reserved_address (lightdag::endpoint const &);
}
static uint64_t endpoint_hash_raw (lightdag::endpoint const & endpoint_a)
{
	assert (endpoint_a.address ().is_v6 ());
	lightdag::uint128_union address;
	address.bytes = endpoint_a.address ().to_v6 ().to_bytes ();
	XXH64_state_t hash;
	XXH64_reset (&hash, 0);
	XXH64_update (&hash, address.bytes.data (), address.bytes.size ());
	auto port (endpoint_a.port ());
	XXH64_update (&hash, &port, sizeof (port));
	auto result (XXH64_digest (&hash));
	return result;
}

namespace std
{
template <size_t size>
struct endpoint_hash
{
};
template <>
struct endpoint_hash<8>
{
	size_t operator() (lightdag::endpoint const & endpoint_a) const
	{
		return endpoint_hash_raw (endpoint_a);
	}
};
template <>
struct endpoint_hash<4>
{
	size_t operator() (lightdag::endpoint const & endpoint_a) const
	{
		uint64_t big (endpoint_hash_raw (endpoint_a));
		uint32_t result (static_cast<uint32_t> (big) ^ static_cast<uint32_t> (big >> 32));
		return result;
	}
};
template <>
struct hash<lightdag::endpoint>
{
	size_t operator() (lightdag::endpoint const & endpoint_a) const
	{
		endpoint_hash<sizeof (size_t)> ehash;
		return ehash (endpoint_a);
	}
};
}
namespace boost
{
template <>
struct hash<lightdag::endpoint>
{
	size_t operator() (lightdag::endpoint const & endpoint_a) const
	{
		std::hash<lightdag::endpoint> hash;
		return hash (endpoint_a);
	}
};
}

namespace lightdag
{
enum class message_type : uint8_t
{
	invalid,
	not_a_type,
	keepalive,
	publish,
	confirm_req,
	confirm_ack,
	bulk_pull,
	bulk_push,
	frontier_req,
	bulk_pull_blocks
};
enum class bulk_pull_blocks_mode : uint8_t
{
	list_blocks,
	checksum_blocks
};
class message_visitor;
class message
{
public:
	message (lightdag::message_type);
	message (bool &, lightdag::stream &);
	virtual ~message () = default;
	void write_header (lightdag::stream &);
	static bool read_header (lightdag::stream &, uint8_t &, uint8_t &, uint8_t &, lightdag::message_type &, std::bitset<16> &);
	virtual void serialize (lightdag::stream &) = 0;
	virtual bool deserialize (lightdag::stream &) = 0;
	virtual void visit (lightdag::message_visitor &) const = 0;
	lightdag::block_type block_type () const;
	void block_type_set (lightdag::block_type);
	bool ipv4_only ();
	void ipv4_only_set (bool);
	static std::array<uint8_t, 2> constexpr magic_number = lightdag::lightdag_network == lightdag::lightdag_networks::lightdag_test_network ? std::array<uint8_t, 2> ({ 'R', 'A' }) : lightdag::lightdag_network == lightdag::lightdag_networks::lightdag_beta_network ? std::array<uint8_t, 2> ({ 'R', 'B' }) : std::array<uint8_t, 2> ({ 'R', 'C' });
	uint8_t version_max;
	uint8_t version_using;
	uint8_t version_min;
	lightdag::message_type type;
	std::bitset<16> extensions;
	static size_t constexpr ipv4_only_position = 1;
	static size_t constexpr bootstrap_server_position = 2;
	static std::bitset<16> constexpr block_type_mask = std::bitset<16> (0x0f00);
};
class work_pool;
class message_parser
{
public:
	enum class parse_status
	{
		success,
		insufficient_work,
		invalid_header,
		invalid_message_type,
		invalid_keepalive_message,
		invalid_publish_message,
		invalid_confirm_req_message,
		invalid_confirm_ack_message
	};
	message_parser (lightdag::message_visitor &, lightdag::work_pool &);
	void deserialize_buffer (uint8_t const *, size_t);
	void deserialize_keepalive (uint8_t const *, size_t);
	void deserialize_publish (uint8_t const *, size_t);
	void deserialize_confirm_req (uint8_t const *, size_t);
	void deserialize_confirm_ack (uint8_t const *, size_t);
	bool at_end (lightdag::bufferstream &);
	lightdag::message_visitor & visitor;
	lightdag::work_pool & pool;
	parse_status status;
};
class keepalive : public message
{
public:
	keepalive ();
	void visit (lightdag::message_visitor &) const override;
	bool deserialize (lightdag::stream &) override;
	void serialize (lightdag::stream &) override;
	bool operator== (lightdag::keepalive const &) const;
	std::array<lightdag::endpoint, 8> peers;
};
class publish : public message
{
public:
	publish ();
	publish (std::shared_ptr<lightdag::block>);
	void visit (lightdag::message_visitor &) const override;
	bool deserialize (lightdag::stream &) override;
	void serialize (lightdag::stream &) override;
	bool operator== (lightdag::publish const &) const;
	std::shared_ptr<lightdag::block> block;
};
class confirm_req : public message
{
public:
	confirm_req ();
	confirm_req (std::shared_ptr<lightdag::block>);
	bool deserialize (lightdag::stream &) override;
	void serialize (lightdag::stream &) override;
	void visit (lightdag::message_visitor &) const override;
	bool operator== (lightdag::confirm_req const &) const;
	std::shared_ptr<lightdag::block> block;
};
class confirm_ack : public message
{
public:
	confirm_ack (bool &, lightdag::stream &);
	confirm_ack (std::shared_ptr<lightdag::vote>);
	bool deserialize (lightdag::stream &) override;
	void serialize (lightdag::stream &) override;
	void visit (lightdag::message_visitor &) const override;
	bool operator== (lightdag::confirm_ack const &) const;
	std::shared_ptr<lightdag::vote> vote;
};
class frontier_req : public message
{
public:
	frontier_req ();
	bool deserialize (lightdag::stream &) override;
	void serialize (lightdag::stream &) override;
	void visit (lightdag::message_visitor &) const override;
	bool operator== (lightdag::frontier_req const &) const;
	lightdag::account start;
	uint32_t age;
	uint32_t count;
};
class bulk_pull : public message
{
public:
	bulk_pull ();
	bool deserialize (lightdag::stream &) override;
	void serialize (lightdag::stream &) override;
	void visit (lightdag::message_visitor &) const override;
	lightdag::uint256_union start;
	lightdag::block_hash end;
};
class bulk_pull_blocks : public message
{
public:
	bulk_pull_blocks ();
	bool deserialize (lightdag::stream &) override;
	void serialize (lightdag::stream &) override;
	void visit (lightdag::message_visitor &) const override;
	lightdag::block_hash min_hash;
	lightdag::block_hash max_hash;
	bulk_pull_blocks_mode mode;
	uint32_t max_count;
};
class bulk_push : public message
{
public:
	bulk_push ();
	bool deserialize (lightdag::stream &) override;
	void serialize (lightdag::stream &) override;
	void visit (lightdag::message_visitor &) const override;
};
class message_visitor
{
public:
	virtual void keepalive (lightdag::keepalive const &) = 0;
	virtual void publish (lightdag::publish const &) = 0;
	virtual void confirm_req (lightdag::confirm_req const &) = 0;
	virtual void confirm_ack (lightdag::confirm_ack const &) = 0;
	virtual void bulk_pull (lightdag::bulk_pull const &) = 0;
	virtual void bulk_pull_blocks (lightdag::bulk_pull_blocks const &) = 0;
	virtual void bulk_push (lightdag::bulk_push const &) = 0;
	virtual void frontier_req (lightdag::frontier_req const &) = 0;
	virtual ~message_visitor ();
};

/**
 * Returns seconds passed since unix epoch (posix time)
 */
inline uint64_t seconds_since_epoch ()
{
	return std::chrono::duration_cast<std::chrono::seconds> (std::chrono::system_clock::now ().time_since_epoch ()).count ();
}
}
