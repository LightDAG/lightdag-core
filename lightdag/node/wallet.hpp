#pragma once

#include <lightdag/blockstore.hpp>
#include <lightdag/common.hpp>
#include <lightdag/node/common.hpp>
#include <lightdag/node/openclwork.hpp>

#include <mutex>
#include <queue>
#include <thread>
#include <unordered_set>

namespace lightdag
{
// The fan spreads a key out over the heap to decrease the likelihood of it being recovered by memory inspection
class fan
{
public:
	fan (lightdag::uint256_union const &, size_t);
	void value (lightdag::raw_key &);
	void value_set (lightdag::raw_key const &);
	std::vector<std::unique_ptr<lightdag::uint256_union>> values;

private:
	std::mutex mutex;
	void value_get (lightdag::raw_key &);
};
class wallet_value
{
public:
	wallet_value () = default;
	wallet_value (lightdag::mdb_val const &);
	wallet_value (lightdag::uint256_union const &, uint64_t);
	lightdag::mdb_val val () const;
	lightdag::private_key key;
	uint64_t work;
};
class node_config;
class kdf
{
public:
	void phs (lightdag::raw_key &, std::string const &, lightdag::uint256_union const &);
	std::mutex mutex;
};
enum class key_type
{
	not_a_type,
	unknown,
	adhoc,
	deterministic
};
class wallet_store
{
public:
	wallet_store (bool &, lightdag::kdf &, lightdag::transaction &, lightdag::account, unsigned, std::string const &);
	wallet_store (bool &, lightdag::kdf &, lightdag::transaction &, lightdag::account, unsigned, std::string const &, std::string const &);
	std::vector<lightdag::account> accounts (MDB_txn *);
	void initialize (MDB_txn *, bool &, std::string const &);
	lightdag::uint256_union check (MDB_txn *);
	bool rekey (MDB_txn *, std::string const &);
	bool valid_password (MDB_txn *);
	bool attempt_password (MDB_txn *, std::string const &);
	void wallet_key (lightdag::raw_key &, MDB_txn *);
	void seed (lightdag::raw_key &, MDB_txn *);
	void seed_set (MDB_txn *, lightdag::raw_key const &);
	lightdag::key_type key_type (lightdag::wallet_value const &);
	lightdag::public_key deterministic_insert (MDB_txn *);
	void deterministic_key (lightdag::raw_key &, MDB_txn *, uint32_t);
	uint32_t deterministic_index_get (MDB_txn *);
	void deterministic_index_set (MDB_txn *, uint32_t);
	void deterministic_clear (MDB_txn *);
	lightdag::uint256_union salt (MDB_txn *);
	bool is_representative (MDB_txn *);
	lightdag::account representative (MDB_txn *);
	void representative_set (MDB_txn *, lightdag::account const &);
	lightdag::public_key insert_adhoc (MDB_txn *, lightdag::raw_key const &);
	void insert_watch (MDB_txn *, lightdag::public_key const &);
	void erase (MDB_txn *, lightdag::public_key const &);
	lightdag::wallet_value entry_get_raw (MDB_txn *, lightdag::public_key const &);
	void entry_put_raw (MDB_txn *, lightdag::public_key const &, lightdag::wallet_value const &);
	bool fetch (MDB_txn *, lightdag::public_key const &, lightdag::raw_key &);
	bool exists (MDB_txn *, lightdag::public_key const &);
	void destroy (MDB_txn *);
	lightdag::store_iterator find (MDB_txn *, lightdag::uint256_union const &);
	lightdag::store_iterator begin (MDB_txn *, lightdag::uint256_union const &);
	lightdag::store_iterator begin (MDB_txn *);
	lightdag::store_iterator end ();
	void derive_key (lightdag::raw_key &, MDB_txn *, std::string const &);
	void serialize_json (MDB_txn *, std::string &);
	void write_backup (MDB_txn *, boost::filesystem::path const &);
	bool move (MDB_txn *, lightdag::wallet_store &, std::vector<lightdag::public_key> const &);
	bool import (MDB_txn *, lightdag::wallet_store &);
	bool work_get (MDB_txn *, lightdag::public_key const &, uint64_t &);
	void work_put (MDB_txn *, lightdag::public_key const &, uint64_t);
	unsigned version (MDB_txn *);
	void version_put (MDB_txn *, unsigned);
	void upgrade_v1_v2 ();
	void upgrade_v2_v3 ();
	lightdag::fan password;
	lightdag::fan wallet_key_mem;
	static unsigned const version_1;
	static unsigned const version_2;
	static unsigned const version_3;
	static unsigned const version_current;
	static lightdag::uint256_union const version_special;
	static lightdag::uint256_union const wallet_key_special;
	static lightdag::uint256_union const salt_special;
	static lightdag::uint256_union const check_special;
	static lightdag::uint256_union const representative_special;
	static lightdag::uint256_union const seed_special;
	static lightdag::uint256_union const deterministic_index_special;
	static int const special_count;
	static unsigned const kdf_full_work = 64 * 1024;
	static unsigned const kdf_test_work = 8;
	static unsigned const kdf_work = lightdag::lightdag_network == lightdag::lightdag_networks::lightdag_test_network ? kdf_test_work : kdf_full_work;
	lightdag::kdf & kdf;
	lightdag::mdb_env & environment;
	MDB_dbi handle;
	std::recursive_mutex mutex;
};
class node;
// A wallet is a set of account keys encrypted by a common encryption key
class wallet : public std::enable_shared_from_this<lightdag::wallet>
{
public:
	std::shared_ptr<lightdag::block> change_action (lightdag::account const &, lightdag::account const &, bool = true);
	std::shared_ptr<lightdag::block> receive_action (lightdag::block const &, lightdag::account const &, lightdag::uint128_union const &, bool = true);
	std::shared_ptr<lightdag::block> send_action (lightdag::account const &, lightdag::account const &, lightdag::uint128_t const &, bool = true, boost::optional<std::string> = {});
	wallet (bool &, lightdag::transaction &, lightdag::node &, std::string const &);
	wallet (bool &, lightdag::transaction &, lightdag::node &, std::string const &, std::string const &);
	void enter_initial_password ();
	bool valid_password ();
	bool enter_password (std::string const &);
	lightdag::public_key insert_adhoc (lightdag::raw_key const &, bool = true);
	lightdag::public_key insert_adhoc (MDB_txn *, lightdag::raw_key const &, bool = true);
	void insert_watch (MDB_txn *, lightdag::public_key const &);
	lightdag::public_key deterministic_insert (MDB_txn *, bool = true);
	lightdag::public_key deterministic_insert (bool = true);
	bool exists (lightdag::public_key const &);
	bool import (std::string const &, std::string const &);
	void serialize (std::string &);
	bool change_sync (lightdag::account const &, lightdag::account const &);
	void change_async (lightdag::account const &, lightdag::account const &, std::function<void(std::shared_ptr<lightdag::block>)> const &, bool = true);
	bool receive_sync (std::shared_ptr<lightdag::block>, lightdag::account const &, lightdag::uint128_t const &);
	void receive_async (std::shared_ptr<lightdag::block>, lightdag::account const &, lightdag::uint128_t const &, std::function<void(std::shared_ptr<lightdag::block>)> const &, bool = true);
	lightdag::block_hash send_sync (lightdag::account const &, lightdag::account const &, lightdag::uint128_t const &);
	void send_async (lightdag::account const &, lightdag::account const &, lightdag::uint128_t const &, std::function<void(std::shared_ptr<lightdag::block>)> const &, bool = true, boost::optional<std::string> = {});
	void work_generate (lightdag::account const &, lightdag::block_hash const &);
	void work_update (MDB_txn *, lightdag::account const &, lightdag::block_hash const &, uint64_t);
	uint64_t work_fetch (MDB_txn *, lightdag::account const &, lightdag::block_hash const &);
	void work_ensure (MDB_txn *, lightdag::account const &);
	bool search_pending ();
	void init_free_accounts (MDB_txn *);
	bool should_generate_state_block (MDB_txn *, lightdag::block_hash const &);
	/** Changes the wallet seed and returns the first account */
	lightdag::public_key change_seed (MDB_txn * transaction_a, lightdag::raw_key const & prv_a);
	std::unordered_set<lightdag::account> free_accounts;
	std::function<void(bool, bool)> lock_observer;
	lightdag::wallet_store store;
	lightdag::node & node;
};
// The wallets set is all the wallets a node controls.  A node may contain multiple wallets independently encrypted and operated.
class wallets
{
public:
	wallets (bool &, lightdag::node &);
	~wallets ();
	std::shared_ptr<lightdag::wallet> open (lightdag::uint256_union const &);
	std::shared_ptr<lightdag::wallet> create (lightdag::uint256_union const &);
	bool search_pending (lightdag::uint256_union const &);
	void search_pending_all ();
	void destroy (lightdag::uint256_union const &);
	void do_wallet_actions ();
	void queue_wallet_action (lightdag::uint128_t const &, std::function<void()> const &);
	void foreach_representative (MDB_txn *, std::function<void(lightdag::public_key const &, lightdag::raw_key const &)> const &);
	bool exists (MDB_txn *, lightdag::public_key const &);
	void stop ();
	std::function<void(bool)> observer;
	std::unordered_map<lightdag::uint256_union, std::shared_ptr<lightdag::wallet>> items;
	std::multimap<lightdag::uint128_t, std::function<void()>, std::greater<lightdag::uint128_t>> actions;
	std::mutex mutex;
	std::condition_variable condition;
	lightdag::kdf kdf;
	MDB_dbi handle;
	MDB_dbi send_action_ids;
	lightdag::node & node;
	bool stopped;
	std::thread thread;
	static lightdag::uint128_t const generate_priority;
	static lightdag::uint128_t const high_priority;
};
}
