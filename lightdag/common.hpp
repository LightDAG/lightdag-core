#pragma once

#include <lightdag/lib/blocks.hpp>
#include <lightdag/node/utility.hpp>

#include <boost/property_tree/ptree.hpp>

#include <unordered_map>

#include <blake2/blake2.h>

namespace boost
{
template <>
struct hash<lightdag::uint256_union>
{
	size_t operator() (lightdag::uint256_union const & value_a) const
	{
		std::hash<lightdag::uint256_union> hash;
		return hash (value_a);
	}
};
}
namespace lightdag
{
class block_store;
/**
 * Determine the balance as of this block
 */
class balance_visitor : public lightdag::block_visitor
{
public:
	balance_visitor (MDB_txn *, lightdag::block_store &);
	virtual ~balance_visitor () = default;
	void compute (lightdag::block_hash const &);
	void send_block (lightdag::send_block const &) override;
	void receive_block (lightdag::receive_block const &) override;
	void open_block (lightdag::open_block const &) override;
	void change_block (lightdag::change_block const &) override;
	void state_block (lightdag::state_block const &) override;
	MDB_txn * transaction;
	lightdag::block_store & store;
	lightdag::block_hash current;
	lightdag::uint128_t result;
};

/**
 * Determine the amount delta resultant from this block
 */
class amount_visitor : public lightdag::block_visitor
{
public:
	amount_visitor (MDB_txn *, lightdag::block_store &);
	virtual ~amount_visitor () = default;
	void compute (lightdag::block_hash const &);
	void send_block (lightdag::send_block const &) override;
	void receive_block (lightdag::receive_block const &) override;
	void open_block (lightdag::open_block const &) override;
	void change_block (lightdag::change_block const &) override;
	void state_block (lightdag::state_block const &) override;
	void from_send (lightdag::block_hash const &);
	MDB_txn * transaction;
	lightdag::block_store & store;
	lightdag::uint128_t result;
};

/**
 * Determine the representative for this block
 */
class representative_visitor : public lightdag::block_visitor
{
public:
	representative_visitor (MDB_txn * transaction_a, lightdag::block_store & store_a);
	virtual ~representative_visitor () = default;
	void compute (lightdag::block_hash const & hash_a);
	void send_block (lightdag::send_block const & block_a) override;
	void receive_block (lightdag::receive_block const & block_a) override;
	void open_block (lightdag::open_block const & block_a) override;
	void change_block (lightdag::change_block const & block_a) override;
	void state_block (lightdag::state_block const & block_a) override;
	MDB_txn * transaction;
	lightdag::block_store & store;
	lightdag::block_hash current;
	lightdag::block_hash result;
};

/**
 * A key pair. The private key is generated from the random pool, or passed in
 * as a hex string. The public key is derived using ed25519.
 */
class keypair
{
public:
	keypair ();
	keypair (std::string const &);
	lightdag::public_key pub;
	lightdag::raw_key prv;
};

std::unique_ptr<lightdag::block> deserialize_block (MDB_val const &);

/**
 * Latest information about an account
 */
class account_info
{
public:
	account_info ();
	account_info (MDB_val const &);
	account_info (lightdag::account_info const &) = default;
	account_info (lightdag::block_hash const &, lightdag::block_hash const &, lightdag::block_hash const &, lightdag::amount const &, uint64_t, uint64_t);
	void serialize (lightdag::stream &) const;
	bool deserialize (lightdag::stream &);
	bool operator== (lightdag::account_info const &) const;
	bool operator!= (lightdag::account_info const &) const;
	lightdag::mdb_val val () const;
	lightdag::block_hash head;
	lightdag::block_hash rep_block;
	lightdag::block_hash open_block;
	lightdag::amount balance;
	/** Seconds since posix epoch */
	uint64_t modified;
	uint64_t block_count;
};

/**
 * Information on an uncollected send, source account, amount, target account.
 */
class pending_info
{
public:
	pending_info ();
	pending_info (MDB_val const &);
	pending_info (lightdag::account const &, lightdag::amount const &);
	void serialize (lightdag::stream &) const;
	bool deserialize (lightdag::stream &);
	bool operator== (lightdag::pending_info const &) const;
	lightdag::mdb_val val () const;
	lightdag::account source;
	lightdag::amount amount;
};
class pending_key
{
public:
	pending_key (lightdag::account const &, lightdag::block_hash const &);
	pending_key (MDB_val const &);
	void serialize (lightdag::stream &) const;
	bool deserialize (lightdag::stream &);
	bool operator== (lightdag::pending_key const &) const;
	lightdag::mdb_val val () const;
	lightdag::account account;
	lightdag::block_hash hash;
};
class block_info
{
public:
	block_info ();
	block_info (MDB_val const &);
	block_info (lightdag::account const &, lightdag::amount const &);
	void serialize (lightdag::stream &) const;
	bool deserialize (lightdag::stream &);
	bool operator== (lightdag::block_info const &) const;
	lightdag::mdb_val val () const;
	lightdag::account account;
	lightdag::amount balance;
};
class block_counts
{
public:
	block_counts ();
	size_t sum ();
	size_t send;
	size_t receive;
	size_t open;
	size_t change;
	size_t state;
};
class vote
{
public:
	vote () = default;
	vote (lightdag::vote const &);
	vote (bool &, lightdag::stream &);
	vote (bool &, lightdag::stream &, lightdag::block_type);
	vote (lightdag::account const &, lightdag::raw_key const &, uint64_t, std::shared_ptr<lightdag::block>);
	vote (MDB_val const &);
	lightdag::uint256_union hash () const;
	bool operator== (lightdag::vote const &) const;
	bool operator!= (lightdag::vote const &) const;
	void serialize (lightdag::stream &, lightdag::block_type);
	void serialize (lightdag::stream &);
	std::string to_json () const;
	// Vote round sequence number
	uint64_t sequence;
	std::shared_ptr<lightdag::block> block;
	// Account that's voting
	lightdag::account account;
	// Signature of sequence + block hash
	lightdag::signature signature;
};
enum class vote_code
{
	invalid, // Vote is not signed correctly
	replay, // Vote does not have the highest sequence number, it's a replay
	vote // Vote has the highest sequence number
};
class vote_result
{
public:
	lightdag::vote_code code;
	std::shared_ptr<lightdag::vote> vote;
};

enum class process_result
{
	progress, // Hasn't been seen before, signed correctly
	bad_signature, // Signature was bad, forged or transmission error
	old, // Already seen and was valid
	negative_spend, // Malicious attempt to spend a negative amount
	fork, // Malicious fork based on previous
	unreceivable, // Source block doesn't exist or has already been received
	gap_previous, // Block marked as previous is unknown
	gap_source, // Block marked as source is unknown
	state_block_disabled, // Awaiting state block canary block
	not_receive_from_send, // Receive does not have a send source
	account_mismatch, // Account number in open block doesn't match send destination
	opened_burn_account, // The impossible happened, someone found the private key associated with the public key '0'.
	balance_mismatch, // Balance and amount delta don't match
	block_position // This block cannot follow the previous block
};
class process_return
{
public:
	lightdag::process_result code;
	lightdag::account account;
	lightdag::amount amount;
	lightdag::account pending_account;
	boost::optional<bool> state_is_send;
};
enum class tally_result
{
	vote,
	changed,
	confirm
};
class votes
{
public:
	votes (std::shared_ptr<lightdag::block>);
	lightdag::tally_result vote (std::shared_ptr<lightdag::vote>);
	// Root block of fork
	lightdag::block_hash id;
	// All votes received by account
	std::unordered_map<lightdag::account, std::shared_ptr<lightdag::block>> rep_votes;
};
extern lightdag::keypair const & zero_key;
extern lightdag::keypair const & test_genesis_key;
extern lightdag::account const & lightdag_test_account;
extern lightdag::account const & lightdag_beta_account;
extern lightdag::account const & lightdag_live_account;
extern std::string const & lightdag_test_genesis;
extern std::string const & lightdag_beta_genesis;
extern std::string const & lightdag_live_genesis;
extern std::string const & genesis_block;
extern lightdag::account const & genesis_account;
extern lightdag::account const & burn_account;
extern lightdag::uint128_t const & genesis_amount;
// A block hash that compares inequal to any real block hash
extern lightdag::block_hash const & not_a_block;
// An account number that compares inequal to any real account number
extern lightdag::block_hash const & not_an_account;
class genesis
{
public:
	explicit genesis ();
	void initialize (MDB_txn *, lightdag::block_store &) const;
	lightdag::block_hash hash () const;
	std::unique_ptr<lightdag::open_block> open;
};
}
