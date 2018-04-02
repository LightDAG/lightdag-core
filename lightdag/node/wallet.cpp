#include <lightdag/node/wallet.hpp>

#include <lightdag/lib/interface.h>
#include <lightdag/node/node.hpp>
#include <lightdag/node/xorshift.hpp>

#include <argon2.h>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <future>

#include <ed25519-donna/ed25519.h>

lightdag::uint256_union lightdag::wallet_store::check (MDB_txn * transaction_a)
{
	lightdag::wallet_value value (entry_get_raw (transaction_a, lightdag::wallet_store::check_special));
	return value.key;
}

lightdag::uint256_union lightdag::wallet_store::salt (MDB_txn * transaction_a)
{
	lightdag::wallet_value value (entry_get_raw (transaction_a, lightdag::wallet_store::salt_special));
	return value.key;
}

void lightdag::wallet_store::wallet_key (lightdag::raw_key & prv_a, MDB_txn * transaction_a)
{
	std::lock_guard<std::recursive_mutex> lock (mutex);
	lightdag::raw_key wallet_l;
	wallet_key_mem.value (wallet_l);
	lightdag::raw_key password_l;
	password.value (password_l);
	prv_a.decrypt (wallet_l.data, password_l, salt (transaction_a).owords[0]);
}

void lightdag::wallet_store::seed (lightdag::raw_key & prv_a, MDB_txn * transaction_a)
{
	lightdag::wallet_value value (entry_get_raw (transaction_a, lightdag::wallet_store::seed_special));
	lightdag::raw_key password_l;
	wallet_key (password_l, transaction_a);
	prv_a.decrypt (value.key, password_l, salt (transaction_a).owords[0]);
}

void lightdag::wallet_store::seed_set (MDB_txn * transaction_a, lightdag::raw_key const & prv_a)
{
	lightdag::raw_key password_l;
	wallet_key (password_l, transaction_a);
	lightdag::uint256_union ciphertext;
	ciphertext.encrypt (prv_a, password_l, salt (transaction_a).owords[0]);
	entry_put_raw (transaction_a, lightdag::wallet_store::seed_special, lightdag::wallet_value (ciphertext, 0));
	deterministic_clear (transaction_a);
}

lightdag::public_key lightdag::wallet_store::deterministic_insert (MDB_txn * transaction_a)
{
	auto index (deterministic_index_get (transaction_a));
	lightdag::raw_key prv;
	deterministic_key (prv, transaction_a, index);
	lightdag::public_key result;
	ed25519_publickey (prv.data.bytes.data (), result.bytes.data ());
	while (exists (transaction_a, result))
	{
		++index;
		deterministic_key (prv, transaction_a, index);
		ed25519_publickey (prv.data.bytes.data (), result.bytes.data ());
	}
	uint64_t marker (1);
	marker <<= 32;
	marker |= index;
	entry_put_raw (transaction_a, result, lightdag::wallet_value (lightdag::uint256_union (marker), 0));
	++index;
	deterministic_index_set (transaction_a, index);
	return result;
}

void lightdag::wallet_store::deterministic_key (lightdag::raw_key & prv_a, MDB_txn * transaction_a, uint32_t index_a)
{
	assert (valid_password (transaction_a));
	lightdag::raw_key seed_l;
	seed (seed_l, transaction_a);
	lightdag::deterministic_key (seed_l.data, index_a, prv_a.data);
}

uint32_t lightdag::wallet_store::deterministic_index_get (MDB_txn * transaction_a)
{
	lightdag::wallet_value value (entry_get_raw (transaction_a, lightdag::wallet_store::deterministic_index_special));
	return value.key.number ().convert_to<uint32_t> ();
}

void lightdag::wallet_store::deterministic_index_set (MDB_txn * transaction_a, uint32_t index_a)
{
	lightdag::uint256_union index_l (index_a);
	lightdag::wallet_value value (index_l, 0);
	entry_put_raw (transaction_a, lightdag::wallet_store::deterministic_index_special, value);
}

void lightdag::wallet_store::deterministic_clear (MDB_txn * transaction_a)
{
	lightdag::uint256_union key (0);
	for (auto i (begin (transaction_a)), n (end ()); i != n;)
	{
		switch (key_type (lightdag::wallet_value (i->second)))
		{
			case lightdag::key_type::deterministic:
			{
				lightdag::uint256_union key (i->first.uint256 ());
				erase (transaction_a, key);
				i = begin (transaction_a, key);
				break;
			}
			default:
			{
				++i;
				break;
			}
		}
	}
	deterministic_index_set (transaction_a, 0);
}

bool lightdag::wallet_store::valid_password (MDB_txn * transaction_a)
{
	lightdag::raw_key zero;
	zero.data.clear ();
	lightdag::raw_key wallet_key_l;
	wallet_key (wallet_key_l, transaction_a);
	lightdag::uint256_union check_l;
	check_l.encrypt (zero, wallet_key_l, salt (transaction_a).owords[0]);
	bool ok = check (transaction_a) == check_l;
	return ok;
}

bool lightdag::wallet_store::attempt_password (MDB_txn * transaction_a, std::string const & password_a)
{
	bool result = false;
	{
		std::lock_guard<std::recursive_mutex> lock (mutex);
		lightdag::raw_key password_l;
		derive_key (password_l, transaction_a, password_a);
		password.value_set (password_l);
		result = !valid_password (transaction_a);
	}
	if (!result)
	{
		if (version (transaction_a) == version_1)
		{
			upgrade_v1_v2 ();
		}
		if (version (transaction_a) == version_2)
		{
			upgrade_v2_v3 ();
		}
	}
	return result;
}

bool lightdag::wallet_store::rekey (MDB_txn * transaction_a, std::string const & password_a)
{
	std::lock_guard<std::recursive_mutex> lock (mutex);
	bool result (false);
	if (valid_password (transaction_a))
	{
		lightdag::raw_key password_new;
		derive_key (password_new, transaction_a, password_a);
		lightdag::raw_key wallet_key_l;
		wallet_key (wallet_key_l, transaction_a);
		lightdag::raw_key password_l;
		password.value (password_l);
		password.value_set (password_new);
		lightdag::uint256_union encrypted;
		encrypted.encrypt (wallet_key_l, password_new, salt (transaction_a).owords[0]);
		lightdag::raw_key wallet_enc;
		wallet_enc.data = encrypted;
		wallet_key_mem.value_set (wallet_enc);
		entry_put_raw (transaction_a, lightdag::wallet_store::wallet_key_special, lightdag::wallet_value (encrypted, 0));
	}
	else
	{
		result = true;
	}
	return result;
}

void lightdag::wallet_store::derive_key (lightdag::raw_key & prv_a, MDB_txn * transaction_a, std::string const & password_a)
{
	auto salt_l (salt (transaction_a));
	kdf.phs (prv_a, password_a, salt_l);
}

lightdag::fan::fan (lightdag::uint256_union const & key, size_t count_a)
{
	std::unique_ptr<lightdag::uint256_union> first (new lightdag::uint256_union (key));
	for (auto i (1); i < count_a; ++i)
	{
		std::unique_ptr<lightdag::uint256_union> entry (new lightdag::uint256_union);
		random_pool.GenerateBlock (entry->bytes.data (), entry->bytes.size ());
		*first ^= *entry;
		values.push_back (std::move (entry));
	}
	values.push_back (std::move (first));
}

void lightdag::fan::value (lightdag::raw_key & prv_a)
{
	std::lock_guard<std::mutex> lock (mutex);
	value_get (prv_a);
}

void lightdag::fan::value_get (lightdag::raw_key & prv_a)
{
	assert (!mutex.try_lock ());
	prv_a.data.clear ();
	for (auto & i : values)
	{
		prv_a.data ^= *i;
	}
}

void lightdag::fan::value_set (lightdag::raw_key const & value_a)
{
	std::lock_guard<std::mutex> lock (mutex);
	lightdag::raw_key value_l;
	value_get (value_l);
	*(values[0]) ^= value_l.data;
	*(values[0]) ^= value_a.data;
}

lightdag::wallet_value::wallet_value (lightdag::mdb_val const & val_a)
{
	assert (val_a.size () == sizeof (*this));
	std::copy (reinterpret_cast<uint8_t const *> (val_a.data ()), reinterpret_cast<uint8_t const *> (val_a.data ()) + sizeof (key), key.chars.begin ());
	std::copy (reinterpret_cast<uint8_t const *> (val_a.data ()) + sizeof (key), reinterpret_cast<uint8_t const *> (val_a.data ()) + sizeof (key) + sizeof (work), reinterpret_cast<char *> (&work));
}

lightdag::wallet_value::wallet_value (lightdag::uint256_union const & key_a, uint64_t work_a) :
key (key_a),
work (work_a)
{
}

lightdag::mdb_val lightdag::wallet_value::val () const
{
	static_assert (sizeof (*this) == sizeof (key) + sizeof (work), "Class not packed");
	return lightdag::mdb_val (sizeof (*this), const_cast<lightdag::wallet_value *> (this));
}

unsigned const lightdag::wallet_store::version_1 (1);
unsigned const lightdag::wallet_store::version_2 (2);
unsigned const lightdag::wallet_store::version_3 (3);
unsigned const lightdag::wallet_store::version_current (version_3);
// Wallet version number
lightdag::uint256_union const lightdag::wallet_store::version_special (0);
// Random number used to salt private key encryption
lightdag::uint256_union const lightdag::wallet_store::salt_special (1);
// Key used to encrypt wallet keys, encrypted itself by the user password
lightdag::uint256_union const lightdag::wallet_store::wallet_key_special (2);
// Check value used to see if password is valid
lightdag::uint256_union const lightdag::wallet_store::check_special (3);
// Representative account to be used if we open a new account
lightdag::uint256_union const lightdag::wallet_store::representative_special (4);
// Wallet seed for deterministic key generation
lightdag::uint256_union const lightdag::wallet_store::seed_special (5);
// Current key index for deterministic keys
lightdag::uint256_union const lightdag::wallet_store::deterministic_index_special (6);
int const lightdag::wallet_store::special_count (7);

lightdag::wallet_store::wallet_store (bool & init_a, lightdag::kdf & kdf_a, lightdag::transaction & transaction_a, lightdag::account representative_a, unsigned fanout_a, std::string const & wallet_a, std::string const & json_a) :
password (0, fanout_a),
wallet_key_mem (0, fanout_a),
kdf (kdf_a),
environment (transaction_a.environment)
{
	init_a = false;
	initialize (transaction_a, init_a, wallet_a);
	if (!init_a)
	{
		MDB_val junk;
		assert (mdb_get (transaction_a, handle, lightdag::mdb_val (version_special), &junk) == MDB_NOTFOUND);
		boost::property_tree::ptree wallet_l;
		std::stringstream istream (json_a);
		try
		{
			boost::property_tree::read_json (istream, wallet_l);
		}
		catch (...)
		{
			init_a = true;
		}
		for (auto i (wallet_l.begin ()), n (wallet_l.end ()); i != n; ++i)
		{
			lightdag::uint256_union key;
			init_a = key.decode_hex (i->first);
			if (!init_a)
			{
				lightdag::uint256_union value;
				init_a = value.decode_hex (wallet_l.get<std::string> (i->first));
				if (!init_a)
				{
					entry_put_raw (transaction_a, key, lightdag::wallet_value (value, 0));
				}
				else
				{
					init_a = true;
				}
			}
			else
			{
				init_a = true;
			}
		}
		init_a |= mdb_get (transaction_a, handle, lightdag::mdb_val (version_special), &junk) != 0;
		init_a |= mdb_get (transaction_a, handle, lightdag::mdb_val (wallet_key_special), &junk) != 0;
		init_a |= mdb_get (transaction_a, handle, lightdag::mdb_val (salt_special), &junk) != 0;
		init_a |= mdb_get (transaction_a, handle, lightdag::mdb_val (check_special), &junk) != 0;
		init_a |= mdb_get (transaction_a, handle, lightdag::mdb_val (representative_special), &junk) != 0;
		lightdag::raw_key key;
		key.data.clear ();
		password.value_set (key);
		key.data = entry_get_raw (transaction_a, lightdag::wallet_store::wallet_key_special).key;
		wallet_key_mem.value_set (key);
	}
}

lightdag::wallet_store::wallet_store (bool & init_a, lightdag::kdf & kdf_a, lightdag::transaction & transaction_a, lightdag::account representative_a, unsigned fanout_a, std::string const & wallet_a) :
password (0, fanout_a),
wallet_key_mem (0, fanout_a),
kdf (kdf_a),
environment (transaction_a.environment)
{
	init_a = false;
	initialize (transaction_a, init_a, wallet_a);
	if (!init_a)
	{
		int version_status;
		MDB_val version_value;
		version_status = mdb_get (transaction_a, handle, lightdag::mdb_val (version_special), &version_value);
		if (version_status == MDB_NOTFOUND)
		{
			version_put (transaction_a, version_current);
			lightdag::uint256_union salt_l;
			random_pool.GenerateBlock (salt_l.bytes.data (), salt_l.bytes.size ());
			entry_put_raw (transaction_a, lightdag::wallet_store::salt_special, lightdag::wallet_value (salt_l, 0));
			// Wallet key is a fixed random key that encrypts all entries
			lightdag::raw_key wallet_key;
			random_pool.GenerateBlock (wallet_key.data.bytes.data (), sizeof (wallet_key.data.bytes));
			lightdag::raw_key password_l;
			password_l.data.clear ();
			password.value_set (password_l);
			lightdag::raw_key zero;
			zero.data.clear ();
			// Wallet key is encrypted by the user's password
			lightdag::uint256_union encrypted;
			encrypted.encrypt (wallet_key, zero, salt_l.owords[0]);
			entry_put_raw (transaction_a, lightdag::wallet_store::wallet_key_special, lightdag::wallet_value (encrypted, 0));
			lightdag::raw_key wallet_key_enc;
			wallet_key_enc.data = encrypted;
			wallet_key_mem.value_set (wallet_key_enc);
			lightdag::uint256_union check;
			check.encrypt (zero, wallet_key, salt_l.owords[0]);
			entry_put_raw (transaction_a, lightdag::wallet_store::check_special, lightdag::wallet_value (check, 0));
			entry_put_raw (transaction_a, lightdag::wallet_store::representative_special, lightdag::wallet_value (representative_a, 0));
			lightdag::raw_key seed;
			random_pool.GenerateBlock (seed.data.bytes.data (), seed.data.bytes.size ());
			seed_set (transaction_a, seed);
			entry_put_raw (transaction_a, lightdag::wallet_store::deterministic_index_special, lightdag::wallet_value (lightdag::uint256_union (0), 0));
		}
	}
	lightdag::raw_key key;
	key.data = entry_get_raw (transaction_a, lightdag::wallet_store::wallet_key_special).key;
	wallet_key_mem.value_set (key);
}

std::vector<lightdag::account> lightdag::wallet_store::accounts (MDB_txn * transaction_a)
{
	std::vector<lightdag::account> result;
	for (auto i (begin (transaction_a)), n (end ()); i != n; ++i)
	{
		lightdag::account account (i->first.uint256 ());
		result.push_back (account);
	}
	return result;
}

void lightdag::wallet_store::initialize (MDB_txn * transaction_a, bool & init_a, std::string const & path_a)
{
	assert (strlen (path_a.c_str ()) == path_a.size ());
	auto error (0);
	error |= mdb_dbi_open (transaction_a, path_a.c_str (), MDB_CREATE, &handle);
	init_a = error != 0;
}

bool lightdag::wallet_store::is_representative (MDB_txn * transaction_a)
{
	return exists (transaction_a, representative (transaction_a));
}

void lightdag::wallet_store::representative_set (MDB_txn * transaction_a, lightdag::account const & representative_a)
{
	entry_put_raw (transaction_a, lightdag::wallet_store::representative_special, lightdag::wallet_value (representative_a, 0));
}

lightdag::account lightdag::wallet_store::representative (MDB_txn * transaction_a)
{
	lightdag::wallet_value value (entry_get_raw (transaction_a, lightdag::wallet_store::representative_special));
	return value.key;
}

lightdag::public_key lightdag::wallet_store::insert_adhoc (MDB_txn * transaction_a, lightdag::raw_key const & prv)
{
	assert (valid_password (transaction_a));
	lightdag::public_key pub;
	ed25519_publickey (prv.data.bytes.data (), pub.bytes.data ());
	lightdag::raw_key password_l;
	wallet_key (password_l, transaction_a);
	lightdag::uint256_union ciphertext;
	ciphertext.encrypt (prv, password_l, salt (transaction_a).owords[0]);
	entry_put_raw (transaction_a, pub, lightdag::wallet_value (ciphertext, 0));
	return pub;
}

void lightdag::wallet_store::insert_watch (MDB_txn * transaction_a, lightdag::public_key const & pub)
{
	entry_put_raw (transaction_a, pub, lightdag::wallet_value (lightdag::uint256_union (0), 0));
}

void lightdag::wallet_store::erase (MDB_txn * transaction_a, lightdag::public_key const & pub)
{
	auto status (mdb_del (transaction_a, handle, lightdag::mdb_val (pub), nullptr));
	assert (status == 0);
}

lightdag::wallet_value lightdag::wallet_store::entry_get_raw (MDB_txn * transaction_a, lightdag::public_key const & pub_a)
{
	lightdag::wallet_value result;
	lightdag::mdb_val value;
	auto status (mdb_get (transaction_a, handle, lightdag::mdb_val (pub_a), value));
	if (status == 0)
	{
		result = lightdag::wallet_value (value);
	}
	else
	{
		result.key.clear ();
		result.work = 0;
	}
	return result;
}

void lightdag::wallet_store::entry_put_raw (MDB_txn * transaction_a, lightdag::public_key const & pub_a, lightdag::wallet_value const & entry_a)
{
	auto status (mdb_put (transaction_a, handle, lightdag::mdb_val (pub_a), entry_a.val (), 0));
	assert (status == 0);
}

lightdag::key_type lightdag::wallet_store::key_type (lightdag::wallet_value const & value_a)
{
	auto number (value_a.key.number ());
	lightdag::key_type result;
	auto text (number.convert_to<std::string> ());
	if (number > std::numeric_limits<uint64_t>::max ())
	{
		result = lightdag::key_type::adhoc;
	}
	else
	{
		if ((number >> 32).convert_to<uint32_t> () == 1)
		{
			result = lightdag::key_type::deterministic;
		}
		else
		{
			result = lightdag::key_type::unknown;
		}
	}
	return result;
}

bool lightdag::wallet_store::fetch (MDB_txn * transaction_a, lightdag::public_key const & pub, lightdag::raw_key & prv)
{
	auto result (false);
	if (valid_password (transaction_a))
	{
		lightdag::wallet_value value (entry_get_raw (transaction_a, pub));
		if (!value.key.is_zero ())
		{
			switch (key_type (value))
			{
				case lightdag::key_type::deterministic:
				{
					lightdag::raw_key seed_l;
					seed (seed_l, transaction_a);
					uint32_t index (value.key.number ().convert_to<uint32_t> ());
					deterministic_key (prv, transaction_a, index);
					break;
				}
				case lightdag::key_type::adhoc:
				{
					// Ad-hoc keys
					lightdag::raw_key password_l;
					wallet_key (password_l, transaction_a);
					prv.decrypt (value.key, password_l, salt (transaction_a).owords[0]);
					break;
				}
				default:
				{
					result = true;
					break;
				}
			}
		}
		else
		{
			result = true;
		}
	}
	else
	{
		result = true;
	}
	if (!result)
	{
		lightdag::public_key compare;
		ed25519_publickey (prv.data.bytes.data (), compare.bytes.data ());
		if (!(pub == compare))
		{
			result = true;
		}
	}
	return result;
}

bool lightdag::wallet_store::exists (MDB_txn * transaction_a, lightdag::public_key const & pub)
{
	return find (transaction_a, pub) != end ();
}

void lightdag::wallet_store::serialize_json (MDB_txn * transaction_a, std::string & string_a)
{
	boost::property_tree::ptree tree;
	for (lightdag::store_iterator i (transaction_a, handle), n (nullptr); i != n; ++i)
	{
		tree.put (lightdag::uint256_union (i->first.uint256 ()).to_string (), lightdag::wallet_value (i->second).key.to_string ());
	}
	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();
}

void lightdag::wallet_store::write_backup (MDB_txn * transaction_a, boost::filesystem::path const & path_a)
{
	std::ofstream backup_file;
	backup_file.open (path_a.string ());
	if (!backup_file.fail ())
	{
		std::string json;
		serialize_json (transaction_a, json);
		backup_file << json;
	}
}

bool lightdag::wallet_store::move (MDB_txn * transaction_a, lightdag::wallet_store & other_a, std::vector<lightdag::public_key> const & keys)
{
	assert (valid_password (transaction_a));
	assert (other_a.valid_password (transaction_a));
	auto result (false);
	for (auto i (keys.begin ()), n (keys.end ()); i != n; ++i)
	{
		lightdag::raw_key prv;
		auto error (other_a.fetch (transaction_a, *i, prv));
		result = result | error;
		if (!result)
		{
			insert_adhoc (transaction_a, prv);
			other_a.erase (transaction_a, *i);
		}
	}
	return result;
}

bool lightdag::wallet_store::import (MDB_txn * transaction_a, lightdag::wallet_store & other_a)
{
	assert (valid_password (transaction_a));
	assert (other_a.valid_password (transaction_a));
	auto result (false);
	for (auto i (other_a.begin (transaction_a)), n (end ()); i != n; ++i)
	{
		lightdag::raw_key prv;
		auto error (other_a.fetch (transaction_a, i->first.uint256 (), prv));
		result = result | error;
		if (!result)
		{
			insert_adhoc (transaction_a, prv);
			other_a.erase (transaction_a, i->first.uint256 ());
		}
	}
	return result;
}

bool lightdag::wallet_store::work_get (MDB_txn * transaction_a, lightdag::public_key const & pub_a, uint64_t & work_a)
{
	auto result (false);
	auto entry (entry_get_raw (transaction_a, pub_a));
	if (!entry.key.is_zero ())
	{
		work_a = entry.work;
	}
	else
	{
		result = true;
	}
	return result;
}

void lightdag::wallet_store::work_put (MDB_txn * transaction_a, lightdag::public_key const & pub_a, uint64_t work_a)
{
	auto entry (entry_get_raw (transaction_a, pub_a));
	assert (!entry.key.is_zero ());
	entry.work = work_a;
	entry_put_raw (transaction_a, pub_a, entry);
}

unsigned lightdag::wallet_store::version (MDB_txn * transaction_a)
{
	lightdag::wallet_value value (entry_get_raw (transaction_a, lightdag::wallet_store::version_special));
	auto entry (value.key);
	auto result (static_cast<unsigned> (entry.bytes[31]));
	return result;
}

void lightdag::wallet_store::version_put (MDB_txn * transaction_a, unsigned version_a)
{
	lightdag::uint256_union entry (version_a);
	entry_put_raw (transaction_a, lightdag::wallet_store::version_special, lightdag::wallet_value (entry, 0));
}

void lightdag::wallet_store::upgrade_v1_v2 ()
{
	lightdag::transaction transaction (environment, nullptr, true);
	assert (version (transaction) == 1);
	lightdag::raw_key zero_password;
	lightdag::wallet_value value (entry_get_raw (transaction, lightdag::wallet_store::wallet_key_special));
	lightdag::raw_key kdf;
	kdf.data.clear ();
	zero_password.decrypt (value.key, kdf, salt (transaction).owords[0]);
	derive_key (kdf, transaction, "");
	lightdag::raw_key empty_password;
	empty_password.decrypt (value.key, kdf, salt (transaction).owords[0]);
	for (auto i (begin (transaction)), n (end ()); i != n; ++i)
	{
		lightdag::public_key key (i->first.uint256 ());
		lightdag::raw_key prv;
		if (fetch (transaction, key, prv))
		{
			// Key failed to decrypt despite valid password
			lightdag::wallet_value data (entry_get_raw (transaction, key));
			prv.decrypt (data.key, zero_password, salt (transaction).owords[0]);
			lightdag::public_key compare;
			ed25519_publickey (prv.data.bytes.data (), compare.bytes.data ());
			if (compare == key)
			{
				// If we successfully decrypted it, rewrite the key back with the correct wallet key
				insert_adhoc (transaction, prv);
			}
			else
			{
				// Also try the empty password
				lightdag::wallet_value data (entry_get_raw (transaction, key));
				prv.decrypt (data.key, empty_password, salt (transaction).owords[0]);
				lightdag::public_key compare;
				ed25519_publickey (prv.data.bytes.data (), compare.bytes.data ());
				if (compare == key)
				{
					// If we successfully decrypted it, rewrite the key back with the correct wallet key
					insert_adhoc (transaction, prv);
				}
			}
		}
	}
	version_put (transaction, 2);
}

void lightdag::wallet_store::upgrade_v2_v3 ()
{
	lightdag::transaction transaction (environment, nullptr, true);
	assert (version (transaction) == 2);
	lightdag::raw_key seed;
	random_pool.GenerateBlock (seed.data.bytes.data (), seed.data.bytes.size ());
	seed_set (transaction, seed);
	entry_put_raw (transaction, lightdag::wallet_store::deterministic_index_special, lightdag::wallet_value (lightdag::uint256_union (0), 0));
	version_put (transaction, 3);
}

void lightdag::kdf::phs (lightdag::raw_key & result_a, std::string const & password_a, lightdag::uint256_union const & salt_a)
{
	std::lock_guard<std::mutex> lock (mutex);
	auto success (argon2_hash (1, lightdag::wallet_store::kdf_work, 1, password_a.data (), password_a.size (), salt_a.bytes.data (), salt_a.bytes.size (), result_a.data.bytes.data (), result_a.data.bytes.size (), NULL, 0, Argon2_d, 0x10));
	assert (success == 0);
	(void)success;
}

lightdag::wallet::wallet (bool & init_a, lightdag::transaction & transaction_a, lightdag::node & node_a, std::string const & wallet_a) :
lock_observer ([](bool, bool) {}),
store (init_a, node_a.wallets.kdf, transaction_a, node_a.config.random_representative (), node_a.config.password_fanout, wallet_a),
node (node_a)
{
}

lightdag::wallet::wallet (bool & init_a, lightdag::transaction & transaction_a, lightdag::node & node_a, std::string const & wallet_a, std::string const & json) :
lock_observer ([](bool, bool) {}),
store (init_a, node_a.wallets.kdf, transaction_a, node_a.config.random_representative (), node_a.config.password_fanout, wallet_a, json),
node (node_a)
{
}

void lightdag::wallet::enter_initial_password ()
{
	lightdag::transaction transaction (store.environment, nullptr, true);
	std::lock_guard<std::recursive_mutex> lock (store.mutex);
	lightdag::raw_key password_l;
	store.password.value (password_l);
	if (password_l.data.is_zero ())
	{
		if (valid_password ())
		{
			// Newly created wallets have a zero key
			store.rekey (transaction, "");
		}
		enter_password ("");
	}
}

bool lightdag::wallet::valid_password ()
{
	lightdag::transaction transaction (store.environment, nullptr, false);
	auto result (store.valid_password (transaction));
	return result;
}

bool lightdag::wallet::enter_password (std::string const & password_a)
{
	lightdag::transaction transaction (store.environment, nullptr, false);
	auto result (store.attempt_password (transaction, password_a));
	if (!result)
	{
		auto this_l (shared_from_this ());
		node.background ([this_l]() {
			this_l->search_pending ();
		});
	}
	lock_observer (result, password_a.empty ());
	return result;
}

lightdag::public_key lightdag::wallet::deterministic_insert (MDB_txn * transaction_a, bool generate_work_a)
{
	lightdag::public_key key (0);
	if (store.valid_password (transaction_a))
	{
		key = store.deterministic_insert (transaction_a);
		if (generate_work_a)
		{
			work_ensure (transaction_a, key);
		}
	}
	return key;
}

lightdag::public_key lightdag::wallet::deterministic_insert (bool generate_work_a)
{
	lightdag::transaction transaction (store.environment, nullptr, true);
	auto result (deterministic_insert (transaction, generate_work_a));
	return result;
}

lightdag::public_key lightdag::wallet::insert_adhoc (MDB_txn * transaction_a, lightdag::raw_key const & key_a, bool generate_work_a)
{
	lightdag::public_key key (0);
	if (store.valid_password (transaction_a))
	{
		key = store.insert_adhoc (transaction_a, key_a);
		if (generate_work_a)
		{
			work_ensure (transaction_a, key);
		}
	}
	return key;
}

lightdag::public_key lightdag::wallet::insert_adhoc (lightdag::raw_key const & account_a, bool generate_work_a)
{
	lightdag::transaction transaction (store.environment, nullptr, true);
	auto result (insert_adhoc (transaction, account_a, generate_work_a));
	return result;
}

void lightdag::wallet::insert_watch (MDB_txn * transaction_a, lightdag::public_key const & pub_a)
{
	store.insert_watch (transaction_a, pub_a);
}

bool lightdag::wallet::exists (lightdag::public_key const & account_a)
{
	lightdag::transaction transaction (store.environment, nullptr, false);
	return store.exists (transaction, account_a);
}

bool lightdag::wallet::import (std::string const & json_a, std::string const & password_a)
{
	auto error (false);
	std::unique_ptr<lightdag::wallet_store> temp;
	{
		lightdag::transaction transaction (store.environment, nullptr, true);
		lightdag::uint256_union id;
		random_pool.GenerateBlock (id.bytes.data (), id.bytes.size ());
		temp.reset (new lightdag::wallet_store (error, node.wallets.kdf, transaction, 0, 1, id.to_string (), json_a));
	}
	if (!error)
	{
		lightdag::transaction transaction (store.environment, nullptr, false);
		error = temp->attempt_password (transaction, password_a);
	}
	lightdag::transaction transaction (store.environment, nullptr, true);
	if (!error)
	{
		error = store.import (transaction, *temp);
	}
	temp->destroy (transaction);
	return error;
}

void lightdag::wallet::serialize (std::string & json_a)
{
	lightdag::transaction transaction (store.environment, nullptr, false);
	store.serialize_json (transaction, json_a);
}

void lightdag::wallet_store::destroy (MDB_txn * transaction_a)
{
	auto status (mdb_drop (transaction_a, handle, 1));
	assert (status == 0);
}

std::shared_ptr<lightdag::block> lightdag::wallet::receive_action (lightdag::block const & send_a, lightdag::account const & representative_a, lightdag::uint128_union const & amount_a, bool generate_work_a)
{
	lightdag::account account;
	auto hash (send_a.hash ());
	std::shared_ptr<lightdag::block> block;
	if (node.config.receive_minimum.number () <= amount_a.number ())
	{
		lightdag::transaction transaction (node.ledger.store.environment, nullptr, false);
		lightdag::pending_info pending_info;
		if (node.store.block_exists (transaction, hash))
		{
			account = node.ledger.block_destination (transaction, send_a);
			if (!node.ledger.store.pending_get (transaction, lightdag::pending_key (account, hash), pending_info))
			{
				lightdag::raw_key prv;
				if (!store.fetch (transaction, account, prv))
				{
					lightdag::account_info info;
					auto new_account (node.ledger.store.account_get (transaction, account, info));
					if (!new_account)
					{
						std::shared_ptr<lightdag::block> rep_block = node.ledger.store.block_get (transaction, info.rep_block);
						assert (rep_block != nullptr);
						if (should_generate_state_block (transaction, info.head))
						{
							block.reset (new lightdag::state_block (account, info.head, rep_block->representative (), info.balance.number () + pending_info.amount.number (), hash, prv, account, generate_work_a ? work_fetch (transaction, account, info.head) : 0));
						}
						else
						{
							block.reset (new lightdag::receive_block (info.head, hash, prv, account, generate_work_a ? work_fetch (transaction, account, info.head) : 0));
						}
					}
					else
					{
						if (node.ledger.state_block_generation_enabled (transaction))
						{
							block.reset (new lightdag::state_block (account, 0, representative_a, pending_info.amount, hash, prv, account, generate_work_a ? work_fetch (transaction, account, account) : 0));
						}
						else
						{
							block.reset (new lightdag::open_block (hash, representative_a, account, prv, account, generate_work_a ? work_fetch (transaction, account, account) : 0));
						}
					}
				}
				else
				{
					BOOST_LOG (node.log) << "Unable to receive, wallet locked";
				}
			}
			else
			{
				// Ledger doesn't have this marked as available to receive anymore
			}
		}
		else
		{
			// Ledger doesn't have this block anymore.
		}
	}
	else
	{
		BOOST_LOG (node.log) << boost::str (boost::format ("Not receiving block %1% due to minimum receive threshold") % hash.to_string ());
		// Someone sent us something below the threshold of receiving
	}
	if (block != nullptr)
	{
		assert (block != nullptr);
		node.block_arrival.add (block->hash ());
		node.block_processor.process_receive_many (block);
		if (generate_work_a)
		{
			auto hash (block->hash ());
			auto this_l (shared_from_this ());
			auto source (account);
			node.wallets.queue_wallet_action (lightdag::wallets::generate_priority, [this_l, source, hash] {
				this_l->work_generate (source, hash);
			});
		}
	}
	return block;
}

std::shared_ptr<lightdag::block> lightdag::wallet::change_action (lightdag::account const & source_a, lightdag::account const & representative_a, bool generate_work_a)
{
	std::shared_ptr<lightdag::block> block;
	{
		lightdag::transaction transaction (store.environment, nullptr, false);
		if (store.valid_password (transaction))
		{
			auto existing (store.find (transaction, source_a));
			if (existing != store.end () && !node.ledger.latest (transaction, source_a).is_zero ())
			{
				lightdag::account_info info;
				auto error1 (node.ledger.store.account_get (transaction, source_a, info));
				assert (!error1);
				lightdag::raw_key prv;
				auto error2 (store.fetch (transaction, source_a, prv));
				assert (!error2);
				if (should_generate_state_block (transaction, info.head))
				{
					block.reset (new lightdag::state_block (source_a, info.head, representative_a, info.balance, 0, prv, source_a, generate_work_a ? work_fetch (transaction, source_a, info.head) : 0));
				}
				else
				{
					block.reset (new lightdag::change_block (info.head, representative_a, prv, source_a, generate_work_a ? work_fetch (transaction, source_a, info.head) : 0));
				}
			}
		}
	}
	if (block != nullptr)
	{
		assert (block != nullptr);
		node.block_arrival.add (block->hash ());
		node.block_processor.process_receive_many (block);
		if (generate_work_a)
		{
			auto hash (block->hash ());
			auto this_l (shared_from_this ());
			node.wallets.queue_wallet_action (lightdag::wallets::generate_priority, [this_l, source_a, hash] {
				this_l->work_generate (source_a, hash);
			});
		}
	}
	return block;
}

std::shared_ptr<lightdag::block> lightdag::wallet::send_action (lightdag::account const & source_a, lightdag::account const & account_a, lightdag::uint128_t const & amount_a, bool generate_work_a, boost::optional<std::string> id_a)
{
	std::shared_ptr<lightdag::block> block;
	boost::optional<lightdag::mdb_val> id_mdb_val;
	if (id_a)
	{
		id_mdb_val = lightdag::mdb_val (id_a->size (), const_cast<char *> (id_a->data ()));
	}
	bool error = false;
	bool cached_block = false;
	{
		lightdag::transaction transaction (store.environment, nullptr, (bool)id_mdb_val);
		if (id_mdb_val)
		{
			lightdag::mdb_val result;
			auto status (mdb_get (transaction, node.wallets.send_action_ids, *id_mdb_val, result));
			if (status == 0)
			{
				auto hash (result.uint256 ());
				block = node.store.block_get (transaction, hash);
				if (block != nullptr)
				{
					cached_block = true;
					node.network.republish_block (transaction, block);
				}
			}
			else if (status != MDB_NOTFOUND)
			{
				error = true;
			}
		}
		if (!error && block == nullptr)
		{
			if (store.valid_password (transaction))
			{
				auto existing (store.find (transaction, source_a));
				if (existing != store.end ())
				{
					auto balance (node.ledger.account_balance (transaction, source_a));
					if (!balance.is_zero () && balance >= amount_a)
					{
						lightdag::account_info info;
						auto error1 (node.ledger.store.account_get (transaction, source_a, info));
						assert (!error1);
						lightdag::raw_key prv;
						auto error2 (store.fetch (transaction, source_a, prv));
						assert (!error2);
						std::shared_ptr<lightdag::block> rep_block = node.ledger.store.block_get (transaction, info.rep_block);
						assert (rep_block != nullptr);
						if (should_generate_state_block (transaction, info.head))
						{
							block.reset (new lightdag::state_block (source_a, info.head, rep_block->representative (), balance - amount_a, account_a, prv, source_a, generate_work_a ? work_fetch (transaction, source_a, info.head) : 0));
						}
						else
						{
							block.reset (new lightdag::send_block (info.head, account_a, balance - amount_a, prv, source_a, generate_work_a ? work_fetch (transaction, source_a, info.head) : 0));
						}
						if (id_mdb_val)
						{
							auto status (mdb_put (transaction, node.wallets.send_action_ids, *id_mdb_val, lightdag::mdb_val (block->hash ()), 0));
							if (status != 0)
							{
								block = nullptr;
								error = true;
							}
						}
					}
				}
			}
		}
	}
	if (!error && block != nullptr && !cached_block)
	{
		node.block_arrival.add (block->hash ());
		node.block_processor.process_receive_many (block);
		auto hash (block->hash ());
		auto this_l (shared_from_this ());
		node.wallets.queue_wallet_action (lightdag::wallets::generate_priority, [this_l, source_a, hash] {
			this_l->work_generate (source_a, hash);
		});
	}
	return block;
}

bool lightdag::wallet::should_generate_state_block (MDB_txn * transaction_a, lightdag::block_hash const & hash_a)
{
	auto head (node.store.block_get (transaction_a, hash_a));
	assert (head != nullptr);
	auto is_state (dynamic_cast<lightdag::state_block *> (head.get ()) != nullptr);
	return is_state || node.ledger.state_block_generation_enabled (transaction_a);
}

bool lightdag::wallet::change_sync (lightdag::account const & source_a, lightdag::account const & representative_a)
{
	std::promise<bool> result;
	change_async (source_a, representative_a, [this, source_a, representative_a, &result](std::shared_ptr<lightdag::block> block_a) {
		result.set_value (block_a == nullptr);
	},
	true);
	return result.get_future ().get ();
}

void lightdag::wallet::change_async (lightdag::account const & source_a, lightdag::account const & representative_a, std::function<void(std::shared_ptr<lightdag::block>)> const & action_a, bool generate_work_a)
{
	node.wallets.queue_wallet_action (lightdag::wallets::high_priority, [this, source_a, representative_a, action_a, generate_work_a]() {
		auto block (change_action (source_a, representative_a, generate_work_a));
		action_a (block);
	});
}

bool lightdag::wallet::receive_sync (std::shared_ptr<lightdag::block> block_a, lightdag::account const & representative_a, lightdag::uint128_t const & amount_a)
{
	std::promise<bool> result;
	receive_async (block_a, representative_a, amount_a, [&result](std::shared_ptr<lightdag::block> block_a) {
		result.set_value (block_a == nullptr);
	},
	true);
	return result.get_future ().get ();
}

void lightdag::wallet::receive_async (std::shared_ptr<lightdag::block> block_a, lightdag::account const & representative_a, lightdag::uint128_t const & amount_a, std::function<void(std::shared_ptr<lightdag::block>)> const & action_a, bool generate_work_a)
{
	//assert (dynamic_cast<lightdag::send_block *> (block_a.get ()) != nullptr);
	node.wallets.queue_wallet_action (amount_a, [this, block_a, representative_a, amount_a, action_a, generate_work_a]() {
		auto block (receive_action (*static_cast<lightdag::block *> (block_a.get ()), representative_a, amount_a, generate_work_a));
		action_a (block);
	});
}

lightdag::block_hash lightdag::wallet::send_sync (lightdag::account const & source_a, lightdag::account const & account_a, lightdag::uint128_t const & amount_a)
{
	std::promise<lightdag::block_hash> result;
	send_async (source_a, account_a, amount_a, [&result](std::shared_ptr<lightdag::block> block_a) {
		result.set_value (block_a->hash ());
	},
	true);
	return result.get_future ().get ();
}

void lightdag::wallet::send_async (lightdag::account const & source_a, lightdag::account const & account_a, lightdag::uint128_t const & amount_a, std::function<void(std::shared_ptr<lightdag::block>)> const & action_a, bool generate_work_a, boost::optional<std::string> id_a)
{
	node.background ([this, source_a, account_a, amount_a, action_a, generate_work_a, id_a]() {
		this->node.wallets.queue_wallet_action (lightdag::wallets::high_priority, [this, source_a, account_a, amount_a, action_a, generate_work_a, id_a]() {
			auto block (send_action (source_a, account_a, amount_a, generate_work_a, id_a));
			action_a (block);
		});
	});
}

// Update work for account if latest root is root_a
void lightdag::wallet::work_update (MDB_txn * transaction_a, lightdag::account const & account_a, lightdag::block_hash const & root_a, uint64_t work_a)
{
	assert (!lightdag::work_validate (root_a, work_a));
	assert (store.exists (transaction_a, account_a));
	auto latest (node.ledger.latest_root (transaction_a, account_a));
	if (latest == root_a)
	{
		store.work_put (transaction_a, account_a, work_a);
	}
	else
	{
		BOOST_LOG (node.log) << "Cached work no longer valid, discarding";
	}
}

// Fetch work for root_a, use cached value if possible
uint64_t lightdag::wallet::work_fetch (MDB_txn * transaction_a, lightdag::account const & account_a, lightdag::block_hash const & root_a)
{
	uint64_t result;
	auto error (store.work_get (transaction_a, account_a, result));
	if (error)
	{
		result = node.generate_work (root_a);
	}
	else if (lightdag::work_validate (root_a, result))
	{
		BOOST_LOG (node.log) << "Cached work invalid, regenerating";
		result = node.generate_work (root_a);
	}

	return result;
}

void lightdag::wallet::work_ensure (MDB_txn * transaction_a, lightdag::account const & account_a)
{
	assert (store.exists (transaction_a, account_a));
	auto root (node.ledger.latest_root (transaction_a, account_a));
	uint64_t work;
	auto error (store.work_get (transaction_a, account_a, work));
	assert (!error);
	if (lightdag::work_validate (root, work))
	{
		auto this_l (shared_from_this ());
		node.background ([this_l, account_a, root]() {
			this_l->work_generate (account_a, root);
		});
	}
}

namespace
{
class search_action : public std::enable_shared_from_this<search_action>
{
public:
	search_action (std::shared_ptr<lightdag::wallet> const & wallet_a, MDB_txn * transaction_a) :
	wallet (wallet_a)
	{
		for (auto i (wallet_a->store.begin (transaction_a)), n (wallet_a->store.end ()); i != n; ++i)
		{
			// Don't search pending for watch-only accounts
			if (!lightdag::wallet_value (i->second).key.is_zero ())
			{
				keys.insert (i->first.uint256 ());
			}
		}
	}
	void run ()
	{
		BOOST_LOG (wallet->node.log) << "Beginning pending block search";
		lightdag::transaction transaction (wallet->node.store.environment, nullptr, false);
		std::unordered_set<lightdag::account> already_searched;
		for (auto i (wallet->node.store.pending_begin (transaction)), n (wallet->node.store.pending_end ()); i != n; ++i)
		{
			lightdag::pending_key key (i->first);
			lightdag::pending_info pending (i->second);
			auto existing (keys.find (key.account));
			if (existing != keys.end ())
			{
				auto amount (pending.amount.number ());
				if (wallet->node.config.receive_minimum.number () <= amount)
				{
					lightdag::account_info info;
					auto error (wallet->node.store.account_get (transaction, pending.source, info));
					assert (!error);
					BOOST_LOG (wallet->node.log) << boost::str (boost::format ("Found a pending block %1% from account %2% with head %3%") % key.hash.to_string () % pending.source.to_account () % info.head.to_string ());
					auto account (pending.source);
					if (already_searched.find (account) == already_searched.end ())
					{
						auto this_l (shared_from_this ());
						std::shared_ptr<lightdag::block> block_l (wallet->node.store.block_get (transaction, info.head));
						wallet->node.background ([this_l, account, block_l] {
							lightdag::transaction transaction (this_l->wallet->node.store.environment, nullptr, true);
							this_l->wallet->node.active.start (transaction, block_l, [this_l, account](std::shared_ptr<lightdag::block>, bool) {
								// If there were any forks for this account they've been rolled back and we can receive anything remaining from this account
								this_l->receive_all (account);
							});
							this_l->wallet->node.network.broadcast_confirm_req (block_l);
						});
						already_searched.insert (account);
					}
				}
				else
				{
					BOOST_LOG (wallet->node.log) << boost::str (boost::format ("Not receiving block %1% due to minimum receive threshold") % key.hash.to_string ());
				}
			}
		}
		BOOST_LOG (wallet->node.log) << "Pending block search phase complete";
	}
	void receive_all (lightdag::account const & account_a)
	{
		BOOST_LOG (wallet->node.log) << boost::str (boost::format ("Account %1% confirmed, receiving all blocks") % account_a.to_account ());
		lightdag::transaction transaction (wallet->node.store.environment, nullptr, false);
		auto representative (wallet->store.representative (transaction));
		for (auto i (wallet->node.store.pending_begin (transaction)), n (wallet->node.store.pending_end ()); i != n; ++i)
		{
			lightdag::pending_key key (i->first);
			lightdag::pending_info pending (i->second);
			if (pending.source == account_a)
			{
				if (wallet->store.exists (transaction, key.account))
				{
					if (wallet->store.valid_password (transaction))
					{
						lightdag::pending_key key (i->first);
						std::shared_ptr<lightdag::block> block (wallet->node.store.block_get (transaction, key.hash));
						auto wallet_l (wallet);
						auto amount (pending.amount.number ());
						BOOST_LOG (wallet_l->node.log) << boost::str (boost::format ("Receiving block: %1%") % block->hash ().to_string ());
						wallet_l->receive_async (block, representative, amount, [wallet_l, block](std::shared_ptr<lightdag::block> block_a) {
							if (block_a == nullptr)
							{
								BOOST_LOG (wallet_l->node.log) << boost::str (boost::format ("Error receiving block %1%") % block->hash ().to_string ());
							}
						},
						true);
					}
					else
					{
						BOOST_LOG (wallet->node.log) << boost::str (boost::format ("Unable to fetch key for: %1%, stopping pending search") % key.account.to_account ());
					}
				}
			}
		}
	}
	std::unordered_set<lightdag::uint256_union> keys;
	std::shared_ptr<lightdag::wallet> wallet;
};
}

bool lightdag::wallet::search_pending ()
{
	lightdag::transaction transaction (store.environment, nullptr, false);
	auto result (!store.valid_password (transaction));
	if (!result)
	{
		auto search (std::make_shared<search_action> (shared_from_this (), transaction));
		node.background ([search]() {
			search->run ();
		});
	}
	else
	{
		BOOST_LOG (node.log) << "Stopping search, wallet is locked";
	}
	return result;
}

void lightdag::wallet::init_free_accounts (MDB_txn * transaction_a)
{
	free_accounts.clear ();
	for (auto i (store.begin (transaction_a)), n (store.end ()); i != n; ++i)
	{
		free_accounts.insert (i->first.uint256 ());
	}
}

lightdag::public_key lightdag::wallet::change_seed (MDB_txn * transaction_a, lightdag::raw_key const & prv_a)
{
	store.seed_set (transaction_a, prv_a);
	auto account = deterministic_insert (transaction_a);
	uint32_t count (0);
	for (uint32_t i (1), n (64); i < n; ++i)
	{
		lightdag::raw_key prv;
		store.deterministic_key (prv, transaction_a, i);
		lightdag::keypair pair (prv.data.to_string ());
		// Check if account received at least 1 block
		auto latest (node.ledger.latest (transaction_a, pair.pub));
		if (!latest.is_zero ())
		{
			count = i;
			// i + 64 - Check additional 64 accounts
			// i/64 - Check additional accounts for large wallets. I.e. 64000/64 = 1000 accounts to check
			n = i + 64 + (i / 64);
		}
		else
		{
			// Check if there are pending blocks for account
			lightdag::account end (pair.pub.number () + 1);
			for (auto ii (node.store.pending_begin (transaction_a, lightdag::pending_key (pair.pub, 0))), nn (node.store.pending_begin (transaction_a, lightdag::pending_key (end, 0))); ii != nn; ++ii)
			{
				count = i;
				n = i + 64 + (i / 64);
				break;
			}
		}
	}
	for (uint32_t i (0); i < count; ++i)
	{
		// Generate work for first 4 accounts only to prevent weak CPU nodes stuck
		account = deterministic_insert (transaction_a, i < 4);
	}

	return account;
}

void lightdag::wallet::work_generate (lightdag::account const & account_a, lightdag::block_hash const & root_a)
{
	auto begin (std::chrono::steady_clock::now ());
	auto work (node.generate_work (root_a));
	if (node.config.logging.work_generation_time ())
	{
		BOOST_LOG (node.log) << "Work generation complete: " << (std::chrono::duration_cast<std::chrono::microseconds> (std::chrono::steady_clock::now () - begin).count ()) << " us";
	}
	lightdag::transaction transaction (store.environment, nullptr, true);
	if (store.exists (transaction, account_a))
	{
		work_update (transaction, account_a, root_a, work);
	}
}

lightdag::wallets::wallets (bool & error_a, lightdag::node & node_a) :
observer ([](bool) {}),
node (node_a),
stopped (false),
thread ([this]() { do_wallet_actions (); })
{
	if (!error_a)
	{
		lightdag::transaction transaction (node.store.environment, nullptr, true);
		auto status (mdb_dbi_open (transaction, nullptr, MDB_CREATE, &handle));
		status |= mdb_dbi_open (transaction, "send_action_ids", MDB_CREATE, &send_action_ids);
		assert (status == 0);
		std::string beginning (lightdag::uint256_union (0).to_string ());
		std::string end ((lightdag::uint256_union (lightdag::uint256_t (0) - lightdag::uint256_t (1))).to_string ());
		for (lightdag::store_iterator i (transaction, handle, lightdag::mdb_val (beginning.size (), const_cast<char *> (beginning.c_str ()))), n (transaction, handle, lightdag::mdb_val (end.size (), const_cast<char *> (end.c_str ()))); i != n; ++i)
		{
			lightdag::uint256_union id;
			std::string text (reinterpret_cast<char const *> (i->first.data ()), i->first.size ());
			auto error (id.decode_hex (text));
			assert (!error);
			assert (items.find (id) == items.end ());
			auto wallet (std::make_shared<lightdag::wallet> (error, transaction, node_a, text));
			if (!error)
			{
				node_a.background ([wallet]() {
					wallet->enter_initial_password ();
				});
				items[id] = wallet;
			}
			else
			{
				// Couldn't open wallet
			}
		}
	}
}

lightdag::wallets::~wallets ()
{
	stop ();
	thread.join ();
}

std::shared_ptr<lightdag::wallet> lightdag::wallets::open (lightdag::uint256_union const & id_a)
{
	std::shared_ptr<lightdag::wallet> result;
	auto existing (items.find (id_a));
	if (existing != items.end ())
	{
		result = existing->second;
	}
	return result;
}

std::shared_ptr<lightdag::wallet> lightdag::wallets::create (lightdag::uint256_union const & id_a)
{
	assert (items.find (id_a) == items.end ());
	std::shared_ptr<lightdag::wallet> result;
	bool error;
	{
		lightdag::transaction transaction (node.store.environment, nullptr, true);
		result = std::make_shared<lightdag::wallet> (error, transaction, node, id_a.to_string ());
	}
	if (!error)
	{
		items[id_a] = result;
		node.background ([result]() {
			result->enter_initial_password ();
		});
	}
	return result;
}

bool lightdag::wallets::search_pending (lightdag::uint256_union const & wallet_a)
{
	auto result (false);
	auto existing (items.find (wallet_a));
	result = existing == items.end ();
	if (!result)
	{
		auto wallet (existing->second);
		result = wallet->search_pending ();
	}
	return result;
}

void lightdag::wallets::search_pending_all ()
{
	for (auto i : items)
	{
		i.second->search_pending ();
	}
}

void lightdag::wallets::destroy (lightdag::uint256_union const & id_a)
{
	lightdag::transaction transaction (node.store.environment, nullptr, true);
	auto existing (items.find (id_a));
	assert (existing != items.end ());
	auto wallet (existing->second);
	items.erase (existing);
	wallet->store.destroy (transaction);
}

void lightdag::wallets::do_wallet_actions ()
{
	std::unique_lock<std::mutex> lock (mutex);
	while (!stopped)
	{
		if (!actions.empty ())
		{
			auto first (actions.begin ());
			auto current (std::move (first->second));
			actions.erase (first);
			lock.unlock ();
			observer (true);
			current ();
			observer (false);
			lock.lock ();
		}
		else
		{
			condition.wait (lock);
		}
	}
}

void lightdag::wallets::queue_wallet_action (lightdag::uint128_t const & amount_a, std::function<void()> const & action_a)
{
	std::lock_guard<std::mutex> lock (mutex);
	actions.insert (std::make_pair (amount_a, std::move (action_a)));
	condition.notify_all ();
}

void lightdag::wallets::foreach_representative (MDB_txn * transaction_a, std::function<void(lightdag::public_key const & pub_a, lightdag::raw_key const & prv_a)> const & action_a)
{
	for (auto i (items.begin ()), n (items.end ()); i != n; ++i)
	{
		auto & wallet (*i->second);
		for (auto j (wallet.store.begin (transaction_a)), m (wallet.store.end ()); j != m; ++j)
		{
			lightdag::account account (j->first.uint256 ());
			if (!node.ledger.weight (transaction_a, account).is_zero ())
			{
				if (wallet.store.valid_password (transaction_a))
				{
					lightdag::raw_key prv;
					auto error (wallet.store.fetch (transaction_a, j->first.uint256 (), prv));
					assert (!error);
					action_a (j->first.uint256 (), prv);
				}
				else
				{
					static auto last_log = std::chrono::steady_clock::time_point ();
					if (last_log < std::chrono::steady_clock::now () - std::chrono::seconds (60))
					{
						last_log = std::chrono::steady_clock::now ();
						BOOST_LOG (node.log) << boost::str (boost::format ("Representative locked inside wallet %1%") % i->first.to_string ());
					}
				}
			}
		}
	}
}

bool lightdag::wallets::exists (MDB_txn * transaction_a, lightdag::public_key const & account_a)
{
	auto result (false);
	for (auto i (items.begin ()), n (items.end ()); !result && i != n; ++i)
	{
		result = i->second->store.exists (transaction_a, account_a);
	}
	return result;
}

void lightdag::wallets::stop ()
{
	std::lock_guard<std::mutex> lock (mutex);
	stopped = true;
	condition.notify_all ();
}

lightdag::uint128_t const lightdag::wallets::generate_priority = std::numeric_limits<lightdag::uint128_t>::max ();
lightdag::uint128_t const lightdag::wallets::high_priority = std::numeric_limits<lightdag::uint128_t>::max () - 1;

lightdag::store_iterator lightdag::wallet_store::begin (MDB_txn * transaction_a)
{
	lightdag::store_iterator result (transaction_a, handle, lightdag::mdb_val (lightdag::uint256_union (special_count)));
	return result;
}

lightdag::store_iterator lightdag::wallet_store::begin (MDB_txn * transaction_a, lightdag::uint256_union const & key)
{
	lightdag::store_iterator result (transaction_a, handle, lightdag::mdb_val (key));
	return result;
}

lightdag::store_iterator lightdag::wallet_store::find (MDB_txn * transaction_a, lightdag::uint256_union const & key)
{
	auto result (begin (transaction_a, key));
	lightdag::store_iterator end (nullptr);
	if (result != end)
	{
		if (lightdag::uint256_union (result->first.uint256 ()) == key)
		{
			return result;
		}
		else
		{
			return end;
		}
	}
	else
	{
		return end;
	}
	return result;
}

lightdag::store_iterator lightdag::wallet_store::end ()
{
	return lightdag::store_iterator (nullptr);
}
