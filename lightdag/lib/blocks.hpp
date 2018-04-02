#pragma once

#include <lightdag/lib/numbers.hpp>

#include <assert.h>
#include <blake2/blake2.h>
#include <boost/property_tree/json_parser.hpp>
#include <streambuf>

namespace lightdag
{
std::string to_string_hex (uint64_t);
bool from_string_hex (std::string const &, uint64_t &);
// We operate on streams of uint8_t by convention
using stream = std::basic_streambuf<uint8_t>;
// Read a raw byte stream the size of `T' and fill value.
template <typename T>
bool read (lightdag::stream & stream_a, T & value)
{
	static_assert (std::is_pod<T>::value, "Can't stream read non-standard layout types");
	auto amount_read (stream_a.sgetn (reinterpret_cast<uint8_t *> (&value), sizeof (value)));
	return amount_read != sizeof (value);
}
template <typename T>
void write (lightdag::stream & stream_a, T const & value)
{
	static_assert (std::is_pod<T>::value, "Can't stream write non-standard layout types");
	auto amount_written (stream_a.sputn (reinterpret_cast<uint8_t const *> (&value), sizeof (value)));
	assert (amount_written == sizeof (value));
}
class block_visitor;
enum class block_type : uint8_t
{
	invalid = 0,
	not_a_block = 1,
	send = 2,
	receive = 3,
	open = 4,
	change = 5,
	state = 6
};
class block
{
public:
	// Return a digest of the hashables in this block.
	lightdag::block_hash hash () const;
	std::string to_json ();
	virtual void hash (blake2b_state &) const = 0;
	virtual uint64_t block_work () const = 0;
	virtual void block_work_set (uint64_t) = 0;
	// Previous block in account's chain, zero for open block
	virtual lightdag::block_hash previous () const = 0;
	// Source block for open/receive blocks, zero otherwise.
	virtual lightdag::block_hash source () const = 0;
	// Previous block or account number for open blocks
	virtual lightdag::block_hash root () const = 0;
	virtual lightdag::account representative () const = 0;
	virtual void serialize (lightdag::stream &) const = 0;
	virtual void serialize_json (std::string &) const = 0;
	virtual void visit (lightdag::block_visitor &) const = 0;
	virtual bool operator== (lightdag::block const &) const = 0;
	virtual lightdag::block_type type () const = 0;
	virtual lightdag::signature block_signature () const = 0;
	virtual void signature_set (lightdag::uint512_union const &) = 0;
	virtual ~block () = default;
	virtual bool valid_predecessor (lightdag::block const &) const = 0;
};
class send_hashables
{
public:
	send_hashables (lightdag::account const &, lightdag::block_hash const &, lightdag::amount const &);
	send_hashables (bool &, lightdag::stream &);
	send_hashables (bool &, boost::property_tree::ptree const &);
	void hash (blake2b_state &) const;
	lightdag::block_hash previous;
	lightdag::account destination;
	lightdag::amount balance;
};
class send_block : public lightdag::block
{
public:
	send_block (lightdag::block_hash const &, lightdag::account const &, lightdag::amount const &, lightdag::raw_key const &, lightdag::public_key const &, uint64_t);
	send_block (bool &, lightdag::stream &);
	send_block (bool &, boost::property_tree::ptree const &);
	virtual ~send_block () = default;
	using lightdag::block::hash;
	void hash (blake2b_state &) const override;
	uint64_t block_work () const override;
	void block_work_set (uint64_t) override;
	lightdag::block_hash previous () const override;
	lightdag::block_hash source () const override;
	lightdag::block_hash root () const override;
	lightdag::account representative () const override;
	void serialize (lightdag::stream &) const override;
	void serialize_json (std::string &) const override;
	bool deserialize (lightdag::stream &);
	bool deserialize_json (boost::property_tree::ptree const &);
	void visit (lightdag::block_visitor &) const override;
	lightdag::block_type type () const override;
	lightdag::signature block_signature () const override;
	void signature_set (lightdag::uint512_union const &) override;
	bool operator== (lightdag::block const &) const override;
	bool operator== (lightdag::send_block const &) const;
	bool valid_predecessor (lightdag::block const &) const override;
	static size_t constexpr size = sizeof (lightdag::account) + sizeof (lightdag::block_hash) + sizeof (lightdag::amount) + sizeof (lightdag::signature) + sizeof (uint64_t);
	send_hashables hashables;
	lightdag::signature signature;
	uint64_t work;
};
class receive_hashables
{
public:
	receive_hashables (lightdag::block_hash const &, lightdag::block_hash const &);
	receive_hashables (bool &, lightdag::stream &);
	receive_hashables (bool &, boost::property_tree::ptree const &);
	void hash (blake2b_state &) const;
	lightdag::block_hash previous;
	lightdag::block_hash source;
};
class receive_block : public lightdag::block
{
public:
	receive_block (lightdag::block_hash const &, lightdag::block_hash const &, lightdag::raw_key const &, lightdag::public_key const &, uint64_t);
	receive_block (bool &, lightdag::stream &);
	receive_block (bool &, boost::property_tree::ptree const &);
	virtual ~receive_block () = default;
	using lightdag::block::hash;
	void hash (blake2b_state &) const override;
	uint64_t block_work () const override;
	void block_work_set (uint64_t) override;
	lightdag::block_hash previous () const override;
	lightdag::block_hash source () const override;
	lightdag::block_hash root () const override;
	lightdag::account representative () const override;
	void serialize (lightdag::stream &) const override;
	void serialize_json (std::string &) const override;
	bool deserialize (lightdag::stream &);
	bool deserialize_json (boost::property_tree::ptree const &);
	void visit (lightdag::block_visitor &) const override;
	lightdag::block_type type () const override;
	lightdag::signature block_signature () const override;
	void signature_set (lightdag::uint512_union const &) override;
	bool operator== (lightdag::block const &) const override;
	bool operator== (lightdag::receive_block const &) const;
	bool valid_predecessor (lightdag::block const &) const override;
	static size_t constexpr size = sizeof (lightdag::block_hash) + sizeof (lightdag::block_hash) + sizeof (lightdag::signature) + sizeof (uint64_t);
	receive_hashables hashables;
	lightdag::signature signature;
	uint64_t work;
};
class open_hashables
{
public:
	open_hashables (lightdag::block_hash const &, lightdag::account const &, lightdag::account const &);
	open_hashables (bool &, lightdag::stream &);
	open_hashables (bool &, boost::property_tree::ptree const &);
	void hash (blake2b_state &) const;
	lightdag::block_hash source;
	lightdag::account representative;
	lightdag::account account;
};
class open_block : public lightdag::block
{
public:
	open_block (lightdag::block_hash const &, lightdag::account const &, lightdag::account const &, lightdag::raw_key const &, lightdag::public_key const &, uint64_t);
	open_block (lightdag::block_hash const &, lightdag::account const &, lightdag::account const &, std::nullptr_t);
	open_block (bool &, lightdag::stream &);
	open_block (bool &, boost::property_tree::ptree const &);
	virtual ~open_block () = default;
	using lightdag::block::hash;
	void hash (blake2b_state &) const override;
	uint64_t block_work () const override;
	void block_work_set (uint64_t) override;
	lightdag::block_hash previous () const override;
	lightdag::block_hash source () const override;
	lightdag::block_hash root () const override;
	lightdag::account representative () const override;
	void serialize (lightdag::stream &) const override;
	void serialize_json (std::string &) const override;
	bool deserialize (lightdag::stream &);
	bool deserialize_json (boost::property_tree::ptree const &);
	void visit (lightdag::block_visitor &) const override;
	lightdag::block_type type () const override;
	lightdag::signature block_signature () const override;
	void signature_set (lightdag::uint512_union const &) override;
	bool operator== (lightdag::block const &) const override;
	bool operator== (lightdag::open_block const &) const;
	bool valid_predecessor (lightdag::block const &) const override;
	static size_t constexpr size = sizeof (lightdag::block_hash) + sizeof (lightdag::account) + sizeof (lightdag::account) + sizeof (lightdag::signature) + sizeof (uint64_t);
	lightdag::open_hashables hashables;
	lightdag::signature signature;
	uint64_t work;
};
class change_hashables
{
public:
	change_hashables (lightdag::block_hash const &, lightdag::account const &);
	change_hashables (bool &, lightdag::stream &);
	change_hashables (bool &, boost::property_tree::ptree const &);
	void hash (blake2b_state &) const;
	lightdag::block_hash previous;
	lightdag::account representative;
};
class change_block : public lightdag::block
{
public:
	change_block (lightdag::block_hash const &, lightdag::account const &, lightdag::raw_key const &, lightdag::public_key const &, uint64_t);
	change_block (bool &, lightdag::stream &);
	change_block (bool &, boost::property_tree::ptree const &);
	virtual ~change_block () = default;
	using lightdag::block::hash;
	void hash (blake2b_state &) const override;
	uint64_t block_work () const override;
	void block_work_set (uint64_t) override;
	lightdag::block_hash previous () const override;
	lightdag::block_hash source () const override;
	lightdag::block_hash root () const override;
	lightdag::account representative () const override;
	void serialize (lightdag::stream &) const override;
	void serialize_json (std::string &) const override;
	bool deserialize (lightdag::stream &);
	bool deserialize_json (boost::property_tree::ptree const &);
	void visit (lightdag::block_visitor &) const override;
	lightdag::block_type type () const override;
	lightdag::signature block_signature () const override;
	void signature_set (lightdag::uint512_union const &) override;
	bool operator== (lightdag::block const &) const override;
	bool operator== (lightdag::change_block const &) const;
	bool valid_predecessor (lightdag::block const &) const override;
	static size_t constexpr size = sizeof (lightdag::block_hash) + sizeof (lightdag::account) + sizeof (lightdag::signature) + sizeof (uint64_t);
	lightdag::change_hashables hashables;
	lightdag::signature signature;
	uint64_t work;
};
class state_hashables
{
public:
	state_hashables (lightdag::account const &, lightdag::block_hash const &, lightdag::account const &, lightdag::amount const &, lightdag::uint256_union const &);
	state_hashables (bool &, lightdag::stream &);
	state_hashables (bool &, boost::property_tree::ptree const &);
	void hash (blake2b_state &) const;
	// Account# / public key that operates this account
	// Uses:
	// Bulk signature validation in advance of further ledger processing
	// Arranging uncomitted transactions by account
	lightdag::account account;
	// Previous transaction in this chain
	lightdag::block_hash previous;
	// Representative of this account
	lightdag::account representative;
	// Current balance of this account
	// Allows lookup of account balance simply by looking at the head block
	lightdag::amount balance;
	// Link field contains source block_hash if receiving, destination account if sending
	lightdag::uint256_union link;
};
class state_block : public lightdag::block
{
public:
	state_block (lightdag::account const &, lightdag::block_hash const &, lightdag::account const &, lightdag::amount const &, lightdag::uint256_union const &, lightdag::raw_key const &, lightdag::public_key const &, uint64_t);
	state_block (bool &, lightdag::stream &);
	state_block (bool &, boost::property_tree::ptree const &);
	virtual ~state_block () = default;
	using lightdag::block::hash;
	void hash (blake2b_state &) const override;
	uint64_t block_work () const override;
	void block_work_set (uint64_t) override;
	lightdag::block_hash previous () const override;
	lightdag::block_hash source () const override;
	lightdag::block_hash root () const override;
	lightdag::account representative () const override;
	void serialize (lightdag::stream &) const override;
	void serialize_json (std::string &) const override;
	bool deserialize (lightdag::stream &);
	bool deserialize_json (boost::property_tree::ptree const &);
	void visit (lightdag::block_visitor &) const override;
	lightdag::block_type type () const override;
	lightdag::signature block_signature () const override;
	void signature_set (lightdag::uint512_union const &) override;
	bool operator== (lightdag::block const &) const override;
	bool operator== (lightdag::state_block const &) const;
	bool valid_predecessor (lightdag::block const &) const override;
	static size_t constexpr size = sizeof (lightdag::account) + sizeof (lightdag::block_hash) + sizeof (lightdag::account) + sizeof (lightdag::amount) + sizeof (lightdag::uint256_union) + sizeof (lightdag::signature) + sizeof (uint64_t);
	lightdag::state_hashables hashables;
	lightdag::signature signature;
	uint64_t work; // Only least 48 least significant bits are encoded
};
class block_visitor
{
public:
	virtual void send_block (lightdag::send_block const &) = 0;
	virtual void receive_block (lightdag::receive_block const &) = 0;
	virtual void open_block (lightdag::open_block const &) = 0;
	virtual void change_block (lightdag::change_block const &) = 0;
	virtual void state_block (lightdag::state_block const &) = 0;
	virtual ~block_visitor () = default;
};
std::unique_ptr<lightdag::block> deserialize_block (lightdag::stream &);
std::unique_ptr<lightdag::block> deserialize_block (lightdag::stream &, lightdag::block_type);
std::unique_ptr<lightdag::block> deserialize_block_json (boost::property_tree::ptree const &);
void serialize_block (lightdag::stream &, lightdag::block const &);
}
