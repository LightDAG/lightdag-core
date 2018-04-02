#pragma once

#include <lightdag/common.hpp>

namespace lightdag
{
class block_store;

class shared_ptr_block_hash
{
public:
	size_t operator() (std::shared_ptr<lightdag::block> const &) const;
	bool operator() (std::shared_ptr<lightdag::block> const &, std::shared_ptr<lightdag::block> const &) const;
};

class ledger
{
public:
	ledger (lightdag::block_store &, lightdag::uint128_t const & = 0, lightdag::block_hash const & = 0, lightdag::block_hash const & = 0);
	std::pair<lightdag::uint128_t, std::shared_ptr<lightdag::block>> winner (MDB_txn *, lightdag::votes const & votes_a);
	// Map of weight -> associated block, ordered greatest to least
	std::map<lightdag::uint128_t, std::shared_ptr<lightdag::block>, std::greater<lightdag::uint128_t>> tally (MDB_txn *, lightdag::votes const &);
	lightdag::account account (MDB_txn *, lightdag::block_hash const &);
	lightdag::uint128_t amount (MDB_txn *, lightdag::block_hash const &);
	lightdag::uint128_t balance (MDB_txn *, lightdag::block_hash const &);
	lightdag::uint128_t account_balance (MDB_txn *, lightdag::account const &);
	lightdag::uint128_t account_pending (MDB_txn *, lightdag::account const &);
	lightdag::uint128_t weight (MDB_txn *, lightdag::account const &);
	std::unique_ptr<lightdag::block> successor (MDB_txn *, lightdag::block_hash const &);
	std::unique_ptr<lightdag::block> forked_block (MDB_txn *, lightdag::block const &);
	lightdag::block_hash latest (MDB_txn *, lightdag::account const &);
	lightdag::block_hash latest_root (MDB_txn *, lightdag::account const &);
	lightdag::block_hash representative (MDB_txn *, lightdag::block_hash const &);
	lightdag::block_hash representative_calculated (MDB_txn *, lightdag::block_hash const &);
	bool block_exists (lightdag::block_hash const &);
	std::string block_text (char const *);
	std::string block_text (lightdag::block_hash const &);
	bool is_send (MDB_txn *, lightdag::state_block const &);
	lightdag::block_hash block_destination (MDB_txn *, lightdag::block const &);
	lightdag::block_hash block_source (MDB_txn *, lightdag::block const &);
	lightdag::uint128_t supply (MDB_txn *);
	lightdag::process_return process (MDB_txn *, lightdag::block const &);
	void rollback (MDB_txn *, lightdag::block_hash const &);
	void change_latest (MDB_txn *, lightdag::account const &, lightdag::block_hash const &, lightdag::account const &, lightdag::uint128_union const &, uint64_t, bool = false);
	void checksum_update (MDB_txn *, lightdag::block_hash const &);
	lightdag::checksum checksum (MDB_txn *, lightdag::account const &, lightdag::account const &);
	void dump_account_chain (lightdag::account const &);
	bool state_block_parsing_enabled (MDB_txn *);
	bool state_block_generation_enabled (MDB_txn *);
	static lightdag::uint128_t const unit;
	lightdag::block_store & store;
	lightdag::uint128_t inactive_supply;
	std::unordered_map<lightdag::account, lightdag::uint128_t> bootstrap_weights;
	uint64_t bootstrap_weight_max_blocks;
	std::atomic<bool> check_bootstrap_weights;
	lightdag::block_hash state_block_parse_canary;
	lightdag::block_hash state_block_generate_canary;
};
};
