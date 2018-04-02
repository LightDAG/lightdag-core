#include <lightdag/common.hpp>

#include <lightdag/blockstore.hpp>
#include <lightdag/lib/interface.h>
#include <lightdag/node/common.hpp>
#include <lightdag/versioning.hpp>

#include <boost/property_tree/json_parser.hpp>

#include <queue>

#include <ed25519-donna/ed25519.h>

// Genesis keys for network variants
namespace
{
char const * test_private_key_data = "34F0A37AAD20F4A260F0A5B3CB3D7FB50673212263E58A380BC10474BB039CE4";
char const * test_public_key_data = "B0311EA55708D6A53C75CDBF88300259C6D018522FE3D4D0A242E431F9E8B6D0"; // ldg_3e3j5tkog48pnny9dmfzj1r16pg8t1e76dz5tmac6iq689wyjfpiij4txtdo
char const * beta_public_key_data = "0311B25E0D1E1D7724BBA5BD523954F1DBCFC01CB8671D55ED2D32C7549FB252"; // ldg_11rjpbh1t9ixgwkdqbfxcawobwgusz13sg595ocytdbkrxcbzekkcqkc3dn1
char const * live_public_key_data = "E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA"; // ldg_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3
char const * test_genesis_data = R"%%%({
	"type": "open",
	"source": "B0311EA55708D6A53C75CDBF88300259C6D018522FE3D4D0A242E431F9E8B6D0",
	"representative": "ldg_3e3j5tkog48pnny9dmfzj1r16pg8t1e76dz5tmac6iq689wyjfpiij4txtdo",
	"account": "ldg_3e3j5tkog48pnny9dmfzj1r16pg8t1e76dz5tmac6iq689wyjfpiij4txtdo",
	"work": "9680625b39d3363d",
	"signature": "ECDA914373A2F0CA1296475BAEE40500A7F0A7AD72A5A80C81D7FAB7F6C802B2CC7DB50F5DD0FB25B2EF11761FA7344A158DD5A700B21BD47DE5BD0F63153A02"
})%%%";

char const * beta_genesis_data = R"%%%({
	"type": "open",
	"source": "0311B25E0D1E1D7724BBA5BD523954F1DBCFC01CB8671D55ED2D32C7549FB252",
	"representative": "ldg_11rjpbh1t9ixgwkdqbfxcawobwgusz13sg595ocytdbkrxcbzekkcqkc3dn1",
	"account": "ldg_11rjpbh1t9ixgwkdqbfxcawobwgusz13sg595ocytdbkrxcbzekkcqkc3dn1",
	"work": "869e17b2bfa36639",
	"signature": "34DF447C7F185673128C3516A657DFEC7906F16C68FB5A8879432E2E4FB908C8ED0DD24BBECFAB3C7852898231544A421DC8CB636EF66C82E1245083EB08EA0F"
})%%%";

char const * live_genesis_data = R"%%%({
	"type": "open",
	"source": "E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA",
	"representative": "ldg_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
	"account": "ldg_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
	"work": "62f05417dd3fb691",
	"signature": "9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02"
})%%%";

class ledger_constants
{
public:
	ledger_constants () :
	zero_key ("0"),
	test_genesis_key (test_private_key_data),
	lightdag_test_account (test_public_key_data),
	lightdag_beta_account (beta_public_key_data),
	lightdag_live_account (live_public_key_data),
	lightdag_test_genesis (test_genesis_data),
	lightdag_beta_genesis (beta_genesis_data),
	lightdag_live_genesis (live_genesis_data),
	genesis_account (lightdag::lightdag_network == lightdag::lightdag_networks::lightdag_test_network ? lightdag_test_account : lightdag::lightdag_network == lightdag::lightdag_networks::lightdag_beta_network ? lightdag_beta_account : lightdag_live_account),
	genesis_block (lightdag::lightdag_network == lightdag::lightdag_networks::lightdag_test_network ? lightdag_test_genesis : lightdag::lightdag_network == lightdag::lightdag_networks::lightdag_beta_network ? lightdag_beta_genesis : lightdag_live_genesis),
	genesis_amount (std::numeric_limits<lightdag::uint128_t>::max ()),
	burn_account (0)
	{
		CryptoPP::AutoSeededRandomPool random_pool;
		// Randomly generating these mean no two nodes will ever have the same sentinel values which protects against some insecure algorithms
		random_pool.GenerateBlock (not_a_block.bytes.data (), not_a_block.bytes.size ());
		random_pool.GenerateBlock (not_an_account.bytes.data (), not_an_account.bytes.size ());
	}
	lightdag::keypair zero_key;
	lightdag::keypair test_genesis_key;
	lightdag::account lightdag_test_account;
	lightdag::account lightdag_beta_account;
	lightdag::account lightdag_live_account;
	std::string lightdag_test_genesis;
	std::string lightdag_beta_genesis;
	std::string lightdag_live_genesis;
	lightdag::account genesis_account;
	std::string genesis_block;
	lightdag::uint128_t genesis_amount;
	lightdag::block_hash not_a_block;
	lightdag::account not_an_account;
	lightdag::account burn_account;
};
ledger_constants globals;
}

size_t constexpr lightdag::send_block::size;
size_t constexpr lightdag::receive_block::size;
size_t constexpr lightdag::open_block::size;
size_t constexpr lightdag::change_block::size;
size_t constexpr lightdag::state_block::size;

lightdag::keypair const & lightdag::zero_key (globals.zero_key);
lightdag::keypair const & lightdag::test_genesis_key (globals.test_genesis_key);
lightdag::account const & lightdag::lightdag_test_account (globals.lightdag_test_account);
lightdag::account const & lightdag::lightdag_beta_account (globals.lightdag_beta_account);
lightdag::account const & lightdag::lightdag_live_account (globals.lightdag_live_account);
std::string const & lightdag::lightdag_test_genesis (globals.lightdag_test_genesis);
std::string const & lightdag::lightdag_beta_genesis (globals.lightdag_beta_genesis);
std::string const & lightdag::lightdag_live_genesis (globals.lightdag_live_genesis);

lightdag::account const & lightdag::genesis_account (globals.genesis_account);
std::string const & lightdag::genesis_block (globals.genesis_block);
lightdag::uint128_t const & lightdag::genesis_amount (globals.genesis_amount);
lightdag::block_hash const & lightdag::not_a_block (globals.not_a_block);
lightdag::block_hash const & lightdag::not_an_account (globals.not_an_account);
lightdag::account const & lightdag::burn_account (globals.burn_account);

lightdag::votes::votes (std::shared_ptr<lightdag::block> block_a) :
id (block_a->root ())
{
	rep_votes.insert (std::make_pair (lightdag::not_an_account, block_a));
}

lightdag::tally_result lightdag::votes::vote (std::shared_ptr<lightdag::vote> vote_a)
{
	lightdag::tally_result result;
	auto existing (rep_votes.find (vote_a->account));
	if (existing == rep_votes.end ())
	{
		// Vote on this block hasn't been seen from rep before
		result = lightdag::tally_result::vote;
		rep_votes.insert (std::make_pair (vote_a->account, vote_a->block));
	}
	else
	{
		if (!(*existing->second == *vote_a->block))
		{
			// Rep changed their vote
			result = lightdag::tally_result::changed;
			existing->second = vote_a->block;
		}
		else
		{
			// Rep vote remained the same
			result = lightdag::tally_result::confirm;
		}
	}
	return result;
}

// Create a new random keypair
lightdag::keypair::keypair ()
{
	random_pool.GenerateBlock (prv.data.bytes.data (), prv.data.bytes.size ());
	ed25519_publickey (prv.data.bytes.data (), pub.bytes.data ());
}

// Create a keypair given a hex string of the private key
lightdag::keypair::keypair (std::string const & prv_a)
{
	auto error (prv.data.decode_hex (prv_a));
	assert (!error);
	ed25519_publickey (prv.data.bytes.data (), pub.bytes.data ());
}

// Serialize a block prefixed with an 8-bit typecode
void lightdag::serialize_block (lightdag::stream & stream_a, lightdag::block const & block_a)
{
	write (stream_a, block_a.type ());
	block_a.serialize (stream_a);
}

std::unique_ptr<lightdag::block> lightdag::deserialize_block (MDB_val const & val_a)
{
	lightdag::bufferstream stream (reinterpret_cast<uint8_t const *> (val_a.mv_data), val_a.mv_size);
	return deserialize_block (stream);
}

lightdag::account_info::account_info () :
head (0),
rep_block (0),
open_block (0),
balance (0),
modified (0),
block_count (0)
{
}

lightdag::account_info::account_info (MDB_val const & val_a)
{
	assert (val_a.mv_size == sizeof (*this));
	static_assert (sizeof (head) + sizeof (rep_block) + sizeof (open_block) + sizeof (balance) + sizeof (modified) + sizeof (block_count) == sizeof (*this), "Class not packed");
	std::copy (reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof (*this), reinterpret_cast<uint8_t *> (this));
}

lightdag::account_info::account_info (lightdag::block_hash const & head_a, lightdag::block_hash const & rep_block_a, lightdag::block_hash const & open_block_a, lightdag::amount const & balance_a, uint64_t modified_a, uint64_t block_count_a) :
head (head_a),
rep_block (rep_block_a),
open_block (open_block_a),
balance (balance_a),
modified (modified_a),
block_count (block_count_a)
{
}

void lightdag::account_info::serialize (lightdag::stream & stream_a) const
{
	write (stream_a, head.bytes);
	write (stream_a, rep_block.bytes);
	write (stream_a, open_block.bytes);
	write (stream_a, balance.bytes);
	write (stream_a, modified);
	write (stream_a, block_count);
}

bool lightdag::account_info::deserialize (lightdag::stream & stream_a)
{
	auto error (read (stream_a, head.bytes));
	if (!error)
	{
		error = read (stream_a, rep_block.bytes);
		if (!error)
		{
			error = read (stream_a, open_block.bytes);
			if (!error)
			{
				error = read (stream_a, balance.bytes);
				if (!error)
				{
					error = read (stream_a, modified);
					if (!error)
					{
						error = read (stream_a, block_count);
					}
				}
			}
		}
	}
	return error;
}

bool lightdag::account_info::operator== (lightdag::account_info const & other_a) const
{
	return head == other_a.head && rep_block == other_a.rep_block && open_block == other_a.open_block && balance == other_a.balance && modified == other_a.modified && block_count == other_a.block_count;
}

bool lightdag::account_info::operator!= (lightdag::account_info const & other_a) const
{
	return !(*this == other_a);
}

lightdag::mdb_val lightdag::account_info::val () const
{
	return lightdag::mdb_val (sizeof (*this), const_cast<lightdag::account_info *> (this));
}

lightdag::block_counts::block_counts () :
send (0),
receive (0),
open (0),
change (0)
{
}

size_t lightdag::block_counts::sum ()
{
	return send + receive + open + change + state;
}

lightdag::pending_info::pending_info () :
source (0),
amount (0)
{
}

lightdag::pending_info::pending_info (MDB_val const & val_a)
{
	assert (val_a.mv_size == sizeof (*this));
	static_assert (sizeof (source) + sizeof (amount) == sizeof (*this), "Packed class");
	std::copy (reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof (*this), reinterpret_cast<uint8_t *> (this));
}

lightdag::pending_info::pending_info (lightdag::account const & source_a, lightdag::amount const & amount_a) :
source (source_a),
amount (amount_a)
{
}

void lightdag::pending_info::serialize (lightdag::stream & stream_a) const
{
	lightdag::write (stream_a, source.bytes);
	lightdag::write (stream_a, amount.bytes);
}

bool lightdag::pending_info::deserialize (lightdag::stream & stream_a)
{
	auto result (lightdag::read (stream_a, source.bytes));
	if (!result)
	{
		result = lightdag::read (stream_a, amount.bytes);
	}
	return result;
}

bool lightdag::pending_info::operator== (lightdag::pending_info const & other_a) const
{
	return source == other_a.source && amount == other_a.amount;
}

lightdag::mdb_val lightdag::pending_info::val () const
{
	return lightdag::mdb_val (sizeof (*this), const_cast<lightdag::pending_info *> (this));
}

lightdag::pending_key::pending_key (lightdag::account const & account_a, lightdag::block_hash const & hash_a) :
account (account_a),
hash (hash_a)
{
}

lightdag::pending_key::pending_key (MDB_val const & val_a)
{
	assert (val_a.mv_size == sizeof (*this));
	static_assert (sizeof (account) + sizeof (hash) == sizeof (*this), "Packed class");
	std::copy (reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof (*this), reinterpret_cast<uint8_t *> (this));
}

void lightdag::pending_key::serialize (lightdag::stream & stream_a) const
{
	lightdag::write (stream_a, account.bytes);
	lightdag::write (stream_a, hash.bytes);
}

bool lightdag::pending_key::deserialize (lightdag::stream & stream_a)
{
	auto error (lightdag::read (stream_a, account.bytes));
	if (!error)
	{
		error = lightdag::read (stream_a, hash.bytes);
	}
	return error;
}

bool lightdag::pending_key::operator== (lightdag::pending_key const & other_a) const
{
	return account == other_a.account && hash == other_a.hash;
}

lightdag::mdb_val lightdag::pending_key::val () const
{
	return lightdag::mdb_val (sizeof (*this), const_cast<lightdag::pending_key *> (this));
}

lightdag::block_info::block_info () :
account (0),
balance (0)
{
}

lightdag::block_info::block_info (MDB_val const & val_a)
{
	assert (val_a.mv_size == sizeof (*this));
	static_assert (sizeof (account) + sizeof (balance) == sizeof (*this), "Packed class");
	std::copy (reinterpret_cast<uint8_t const *> (val_a.mv_data), reinterpret_cast<uint8_t const *> (val_a.mv_data) + sizeof (*this), reinterpret_cast<uint8_t *> (this));
}

lightdag::block_info::block_info (lightdag::account const & account_a, lightdag::amount const & balance_a) :
account (account_a),
balance (balance_a)
{
}

void lightdag::block_info::serialize (lightdag::stream & stream_a) const
{
	lightdag::write (stream_a, account.bytes);
	lightdag::write (stream_a, balance.bytes);
}

bool lightdag::block_info::deserialize (lightdag::stream & stream_a)
{
	auto error (lightdag::read (stream_a, account.bytes));
	if (!error)
	{
		error = lightdag::read (stream_a, balance.bytes);
	}
	return error;
}

bool lightdag::block_info::operator== (lightdag::block_info const & other_a) const
{
	return account == other_a.account && balance == other_a.balance;
}

lightdag::mdb_val lightdag::block_info::val () const
{
	return lightdag::mdb_val (sizeof (*this), const_cast<lightdag::block_info *> (this));
}

bool lightdag::vote::operator== (lightdag::vote const & other_a) const
{
	return sequence == other_a.sequence && *block == *other_a.block && account == other_a.account && signature == other_a.signature;
}

bool lightdag::vote::operator!= (lightdag::vote const & other_a) const
{
	return !(*this == other_a);
}

std::string lightdag::vote::to_json () const
{
	std::stringstream stream;
	boost::property_tree::ptree tree;
	tree.put ("account", account.to_account ());
	tree.put ("signature", signature.number ());
	tree.put ("sequence", std::to_string (sequence));
	tree.put ("block", block->to_json ());
	boost::property_tree::write_json (stream, tree);
	return stream.str ();
}

lightdag::amount_visitor::amount_visitor (MDB_txn * transaction_a, lightdag::block_store & store_a) :
transaction (transaction_a),
store (store_a)
{
}

void lightdag::amount_visitor::send_block (lightdag::send_block const & block_a)
{
	balance_visitor prev (transaction, store);
	prev.compute (block_a.hashables.previous);
	result = prev.result - block_a.hashables.balance.number ();
}

void lightdag::amount_visitor::receive_block (lightdag::receive_block const & block_a)
{
	from_send (block_a.hashables.source);
}

void lightdag::amount_visitor::open_block (lightdag::open_block const & block_a)
{
	if (block_a.hashables.source != lightdag::genesis_account)
	{
		from_send (block_a.hashables.source);
	}
	else
	{
		result = lightdag::genesis_amount;
	}
}

void lightdag::amount_visitor::state_block (lightdag::state_block const & block_a)
{
	balance_visitor prev (transaction, store);
	prev.compute (block_a.hashables.previous);
	result = block_a.hashables.balance.number ();
	result = result < prev.result ? prev.result - result : result - prev.result;
}

void lightdag::amount_visitor::change_block (lightdag::change_block const & block_a)
{
	result = 0;
}

void lightdag::amount_visitor::from_send (lightdag::block_hash const & hash_a)
{
	auto source_block (store.block_get (transaction, hash_a));
	assert (source_block != nullptr);
	source_block->visit (*this);
}

void lightdag::amount_visitor::compute (lightdag::block_hash const & block_hash)
{
	auto block (store.block_get (transaction, block_hash));
	if (block != nullptr)
	{
		block->visit (*this);
	}
	else
	{
		if (block_hash == lightdag::genesis_account)
		{
			result = std::numeric_limits<lightdag::uint128_t>::max ();
		}
		else
		{
			assert (false);
			result = 0;
		}
	}
}

lightdag::balance_visitor::balance_visitor (MDB_txn * transaction_a, lightdag::block_store & store_a) :
transaction (transaction_a),
store (store_a),
current (0),
result (0)
{
}

void lightdag::balance_visitor::send_block (lightdag::send_block const & block_a)
{
	result += block_a.hashables.balance.number ();
	current = 0;
}

void lightdag::balance_visitor::receive_block (lightdag::receive_block const & block_a)
{
	amount_visitor source (transaction, store);
	source.compute (block_a.hashables.source);
	lightdag::block_info block_info;
	if (!store.block_info_get (transaction, block_a.hash (), block_info))
	{
		result += block_info.balance.number ();
		current = 0;
	}
	else
	{
		result += source.result;
		current = block_a.hashables.previous;
	}
}

void lightdag::balance_visitor::open_block (lightdag::open_block const & block_a)
{
	amount_visitor source (transaction, store);
	source.compute (block_a.hashables.source);
	result += source.result;
	current = 0;
}

void lightdag::balance_visitor::change_block (lightdag::change_block const & block_a)
{
	lightdag::block_info block_info;
	if (!store.block_info_get (transaction, block_a.hash (), block_info))
	{
		result += block_info.balance.number ();
		current = 0;
	}
	else
	{
		current = block_a.hashables.previous;
	}
}

void lightdag::balance_visitor::state_block (lightdag::state_block const & block_a)
{
	result = block_a.hashables.balance.number ();
	current = 0;
}

void lightdag::balance_visitor::compute (lightdag::block_hash const & block_hash)
{
	current = block_hash;
	while (!current.is_zero ())
	{
		auto block (store.block_get (transaction, current));
		assert (block != nullptr);
		block->visit (*this);
	}
}

lightdag::representative_visitor::representative_visitor (MDB_txn * transaction_a, lightdag::block_store & store_a) :
transaction (transaction_a),
store (store_a),
result (0)
{
}

void lightdag::representative_visitor::compute (lightdag::block_hash const & hash_a)
{
	current = hash_a;
	while (result.is_zero ())
	{
		auto block (store.block_get (transaction, current));
		assert (block != nullptr);
		block->visit (*this);
	}
}

void lightdag::representative_visitor::send_block (lightdag::send_block const & block_a)
{
	current = block_a.previous ();
}

void lightdag::representative_visitor::receive_block (lightdag::receive_block const & block_a)
{
	current = block_a.previous ();
}

void lightdag::representative_visitor::open_block (lightdag::open_block const & block_a)
{
	result = block_a.hash ();
}

void lightdag::representative_visitor::change_block (lightdag::change_block const & block_a)
{
	result = block_a.hash ();
}

void lightdag::representative_visitor::state_block (lightdag::state_block const & block_a)
{
	result = block_a.hash ();
}

lightdag::vote::vote (lightdag::vote const & other_a) :
sequence (other_a.sequence),
block (other_a.block),
account (other_a.account),
signature (other_a.signature)
{
}

lightdag::vote::vote (bool & error_a, lightdag::stream & stream_a)
{
	if (!error_a)
	{
		error_a = lightdag::read (stream_a, account.bytes);
		if (!error_a)
		{
			error_a = lightdag::read (stream_a, signature.bytes);
			if (!error_a)
			{
				error_a = lightdag::read (stream_a, sequence);
				if (!error_a)
				{
					block = lightdag::deserialize_block (stream_a);
					error_a = block == nullptr;
				}
			}
		}
	}
}

lightdag::vote::vote (bool & error_a, lightdag::stream & stream_a, lightdag::block_type type_a)
{
	if (!error_a)
	{
		error_a = lightdag::read (stream_a, account.bytes);
		if (!error_a)
		{
			error_a = lightdag::read (stream_a, signature.bytes);
			if (!error_a)
			{
				error_a = lightdag::read (stream_a, sequence);
				if (!error_a)
				{
					block = lightdag::deserialize_block (stream_a, type_a);
					error_a = block == nullptr;
				}
			}
		}
	}
}

lightdag::vote::vote (lightdag::account const & account_a, lightdag::raw_key const & prv_a, uint64_t sequence_a, std::shared_ptr<lightdag::block> block_a) :
sequence (sequence_a),
block (block_a),
account (account_a),
signature (lightdag::sign_message (prv_a, account_a, hash ()))
{
}

lightdag::vote::vote (MDB_val const & value_a)
{
	lightdag::bufferstream stream (reinterpret_cast<uint8_t const *> (value_a.mv_data), value_a.mv_size);
	auto error (lightdag::read (stream, account.bytes));
	assert (!error);
	error = lightdag::read (stream, signature.bytes);
	assert (!error);
	error = lightdag::read (stream, sequence);
	assert (!error);
	block = lightdag::deserialize_block (stream);
	assert (block != nullptr);
}

lightdag::uint256_union lightdag::vote::hash () const
{
	lightdag::uint256_union result;
	blake2b_state hash;
	blake2b_init (&hash, sizeof (result.bytes));
	blake2b_update (&hash, block->hash ().bytes.data (), sizeof (result.bytes));
	union
	{
		uint64_t qword;
		std::array<uint8_t, 8> bytes;
	};
	qword = sequence;
	blake2b_update (&hash, bytes.data (), sizeof (bytes));
	blake2b_final (&hash, result.bytes.data (), sizeof (result.bytes));
	return result;
}

void lightdag::vote::serialize (lightdag::stream & stream_a, lightdag::block_type)
{
	write (stream_a, account);
	write (stream_a, signature);
	write (stream_a, sequence);
	block->serialize (stream_a);
}

void lightdag::vote::serialize (lightdag::stream & stream_a)
{
	write (stream_a, account);
	write (stream_a, signature);
	write (stream_a, sequence);
	lightdag::serialize_block (stream_a, *block);
}

lightdag::genesis::genesis ()
{
	boost::property_tree::ptree tree;
	std::stringstream istream (lightdag::genesis_block);
	boost::property_tree::read_json (istream, tree);
	auto block (lightdag::deserialize_block_json (tree));
	assert (dynamic_cast<lightdag::open_block *> (block.get ()) != nullptr);
	open.reset (static_cast<lightdag::open_block *> (block.release ()));
}

void lightdag::genesis::initialize (MDB_txn * transaction_a, lightdag::block_store & store_a) const
{
	auto hash_l (hash ());
	assert (store_a.latest_begin (transaction_a) == store_a.latest_end ());
	store_a.block_put (transaction_a, hash_l, *open);
	store_a.account_put (transaction_a, genesis_account, { hash_l, open->hash (), open->hash (), std::numeric_limits<lightdag::uint128_t>::max (), lightdag::seconds_since_epoch (), 1 });
	store_a.representation_put (transaction_a, genesis_account, std::numeric_limits<lightdag::uint128_t>::max ());
	store_a.checksum_put (transaction_a, 0, 0, hash_l);
	store_a.frontier_put (transaction_a, hash_l, genesis_account);
}

lightdag::block_hash lightdag::genesis::hash () const
{
	return open->hash ();
}
