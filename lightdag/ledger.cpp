#include <lightdag/blockstore.hpp>
#include <lightdag/ledger.hpp>
#include <lightdag/node/common.hpp>

namespace
{
/**
 * Roll back the visited block
 */
class rollback_visitor : public lightdag::block_visitor
{
public:
	rollback_visitor (MDB_txn * transaction_a, lightdag::ledger & ledger_a) :
	transaction (transaction_a),
	ledger (ledger_a)
	{
	}
	virtual ~rollback_visitor () = default;
	void send_block (lightdag::send_block const & block_a) override
	{
		auto hash (block_a.hash ());
		lightdag::pending_info pending;
		lightdag::pending_key key (block_a.hashables.destination, hash);
		while (ledger.store.pending_get (transaction, key, pending))
		{
			ledger.rollback (transaction, ledger.latest (transaction, block_a.hashables.destination));
		}
		lightdag::account_info info;
		auto error (ledger.store.account_get (transaction, pending.source, info));
		assert (!error);
		ledger.store.pending_del (transaction, key);
		ledger.store.representation_add (transaction, ledger.representative (transaction, hash), pending.amount.number ());
		ledger.change_latest (transaction, pending.source, block_a.hashables.previous, info.rep_block, ledger.balance (transaction, block_a.hashables.previous), info.block_count - 1);
		ledger.store.block_del (transaction, hash);
		ledger.store.frontier_del (transaction, hash);
		ledger.store.frontier_put (transaction, block_a.hashables.previous, pending.source);
		ledger.store.block_successor_clear (transaction, block_a.hashables.previous);
		if (!(info.block_count % ledger.store.block_info_max))
		{
			ledger.store.block_info_del (transaction, hash);
		}
	}
	void receive_block (lightdag::receive_block const & block_a) override
	{
		auto hash (block_a.hash ());
		auto representative (ledger.representative (transaction, block_a.hashables.previous));
		auto amount (ledger.amount (transaction, block_a.hashables.source));
		auto destination_account (ledger.account (transaction, hash));
		auto source_account (ledger.account (transaction, block_a.hashables.source));
		lightdag::account_info info;
		auto error (ledger.store.account_get (transaction, destination_account, info));
		assert (!error);
		ledger.store.representation_add (transaction, ledger.representative (transaction, hash), 0 - amount);
		ledger.change_latest (transaction, destination_account, block_a.hashables.previous, representative, ledger.balance (transaction, block_a.hashables.previous), info.block_count - 1);
		ledger.store.block_del (transaction, hash);
		ledger.store.pending_put (transaction, lightdag::pending_key (destination_account, block_a.hashables.source), { source_account, amount });
		ledger.store.frontier_del (transaction, hash);
		ledger.store.frontier_put (transaction, block_a.hashables.previous, destination_account);
		ledger.store.block_successor_clear (transaction, block_a.hashables.previous);
		if (!(info.block_count % ledger.store.block_info_max))
		{
			ledger.store.block_info_del (transaction, hash);
		}
	}
	void open_block (lightdag::open_block const & block_a) override
	{
		auto hash (block_a.hash ());
		auto amount (ledger.amount (transaction, block_a.hashables.source));
		auto destination_account (ledger.account (transaction, hash));
		auto source_account (ledger.account (transaction, block_a.hashables.source));
		ledger.store.representation_add (transaction, ledger.representative (transaction, hash), 0 - amount);
		ledger.change_latest (transaction, destination_account, 0, 0, 0, 0);
		ledger.store.block_del (transaction, hash);
		ledger.store.pending_put (transaction, lightdag::pending_key (destination_account, block_a.hashables.source), { source_account, amount });
		ledger.store.frontier_del (transaction, hash);
	}
	void change_block (lightdag::change_block const & block_a) override
	{
		auto hash (block_a.hash ());
		auto representative (ledger.representative (transaction, block_a.hashables.previous));
		auto account (ledger.account (transaction, block_a.hashables.previous));
		lightdag::account_info info;
		auto error (ledger.store.account_get (transaction, account, info));
		assert (!error);
		auto balance (ledger.balance (transaction, block_a.hashables.previous));
		ledger.store.representation_add (transaction, representative, balance);
		ledger.store.representation_add (transaction, hash, 0 - balance);
		ledger.store.block_del (transaction, hash);
		ledger.change_latest (transaction, account, block_a.hashables.previous, representative, info.balance, info.block_count - 1);
		ledger.store.frontier_del (transaction, hash);
		ledger.store.frontier_put (transaction, block_a.hashables.previous, account);
		ledger.store.block_successor_clear (transaction, block_a.hashables.previous);
		if (!(info.block_count % ledger.store.block_info_max))
		{
			ledger.store.block_info_del (transaction, hash);
		}
	}
	void state_block (lightdag::state_block const & block_a) override
	{
		auto hash (block_a.hash ());
		lightdag::block_hash representative (0);
		if (!block_a.hashables.previous.is_zero ())
		{
			representative = ledger.representative (transaction, block_a.hashables.previous);
		}
		auto balance (ledger.balance (transaction, block_a.hashables.previous));
		auto is_send (block_a.hashables.balance < balance);
		// Add in amount delta
		ledger.store.representation_add (transaction, hash, 0 - block_a.hashables.balance.number ());
		if (!representative.is_zero ())
		{
			// Move existing representation
			ledger.store.representation_add (transaction, representative, balance);
		}

		if (is_send)
		{
			lightdag::pending_key key (block_a.hashables.link, hash);
			while (!ledger.store.pending_exists (transaction, key))
			{
				ledger.rollback (transaction, ledger.latest (transaction, block_a.hashables.link));
			}
			ledger.store.pending_del (transaction, key);
		}
		else if (!block_a.hashables.link.is_zero ())
		{
			lightdag::pending_info info (ledger.account (transaction, block_a.hashables.link), block_a.hashables.balance.number () - balance);
			ledger.store.pending_put (transaction, lightdag::pending_key (block_a.hashables.account, block_a.hashables.link), info);
		}

		lightdag::account_info info;
		auto error (ledger.store.account_get (transaction, block_a.hashables.account, info));
		assert (!error);
		ledger.change_latest (transaction, block_a.hashables.account, block_a.hashables.previous, representative, balance, info.block_count - 1);

		auto previous (ledger.store.block_get (transaction, block_a.hashables.previous));
		if (previous != nullptr)
		{
			ledger.store.block_successor_clear (transaction, block_a.hashables.previous);
			switch (previous->type ())
			{
				case lightdag::block_type::send:
				case lightdag::block_type::receive:
				case lightdag::block_type::open:
				case lightdag::block_type::change:
				{
					ledger.store.frontier_put (transaction, block_a.hashables.previous, block_a.hashables.account);
					break;
				}
				default:
					break;
			}
		}
		ledger.store.block_del (transaction, hash);
	}
	MDB_txn * transaction;
	lightdag::ledger & ledger;
};

class ledger_processor : public lightdag::block_visitor
{
public:
	ledger_processor (lightdag::ledger &, MDB_txn *);
	virtual ~ledger_processor () = default;
	void send_block (lightdag::send_block const &) override;
	void receive_block (lightdag::receive_block const &) override;
	void open_block (lightdag::open_block const &) override;
	void change_block (lightdag::change_block const &) override;
	void state_block (lightdag::state_block const &) override;
	void state_block_impl (lightdag::state_block const &);
	lightdag::ledger & ledger;
	MDB_txn * transaction;
	lightdag::process_return result;
};

void ledger_processor::state_block (lightdag::state_block const & block_a)
{
	result.code = ledger.state_block_parsing_enabled (transaction) ? lightdag::process_result::progress : lightdag::process_result::state_block_disabled;
	if (result.code == lightdag::process_result::progress)
	{
		state_block_impl (block_a);
	}
}

void ledger_processor::state_block_impl (lightdag::state_block const & block_a)
{
	auto hash (block_a.hash ());
	auto existing (ledger.store.block_exists (transaction, hash));
	result.code = existing ? lightdag::process_result::old : lightdag::process_result::progress; // Have we seen this block before? (Unambiguous)
	if (result.code == lightdag::process_result::progress)
	{
		result.code = validate_message (block_a.hashables.account, hash, block_a.signature) ? lightdag::process_result::bad_signature : lightdag::process_result::progress; // Is this block signed correctly (Unambiguous)
		if (result.code == lightdag::process_result::progress)
		{
			result.code = block_a.hashables.account.is_zero () ? lightdag::process_result::opened_burn_account : lightdag::process_result::progress; // Is this for the burn account? (Unambiguous)
			if (result.code == lightdag::process_result::progress)
			{
				lightdag::account_info info;
				result.amount = block_a.hashables.balance;
				auto is_send (false);
				auto account_error (ledger.store.account_get (transaction, block_a.hashables.account, info));
				if (!account_error)
				{
					// Account already exists
					result.code = block_a.hashables.previous.is_zero () ? lightdag::process_result::fork : lightdag::process_result::progress; // Has this account already been opened? (Ambigious)
					if (result.code == lightdag::process_result::progress)
					{
						result.code = ledger.store.block_exists (transaction, block_a.hashables.previous) ? lightdag::process_result::progress : lightdag::process_result::gap_previous; // Does the previous block exist in the ledger? (Unambigious)
						if (result.code == lightdag::process_result::progress)
						{
							is_send = block_a.hashables.balance < info.balance;
							result.amount = result.amount.number () - info.balance.number ();
							result.code = block_a.hashables.previous == info.head ? lightdag::process_result::progress : lightdag::process_result::fork; // Is the previous block the account's head block? (Ambigious)
						}
					}
				}
				else
				{
					// Account does not yet exists
					result.code = block_a.previous ().is_zero () ? lightdag::process_result::progress : lightdag::process_result::gap_previous; // Does the first block in an account yield 0 for previous() ? (Unambigious)
					if (result.code == lightdag::process_result::progress)
					{
						result.code = !block_a.hashables.link.is_zero () ? lightdag::process_result::progress : lightdag::process_result::gap_source; // Is the first block receiving from a send ? (Unambigious)
					}
				}
				if (result.code == lightdag::process_result::progress)
				{
					if (!is_send)
					{
						if (!block_a.hashables.link.is_zero ())
						{
							result.code = ledger.store.block_exists (transaction, block_a.hashables.link) ? lightdag::process_result::progress : lightdag::process_result::gap_source; // Have we seen the source block already? (Harmless)
							if (result.code == lightdag::process_result::progress)
							{
								lightdag::pending_key key (block_a.hashables.account, block_a.hashables.link);
								lightdag::pending_info pending;
								result.code = ledger.store.pending_get (transaction, key, pending) ? lightdag::process_result::unreceivable : lightdag::process_result::progress; // Has this source already been received (Malformed)
								if (result.code == lightdag::process_result::progress)
								{
									result.code = result.amount == pending.amount ? lightdag::process_result::progress : lightdag::process_result::balance_mismatch;
								}
							}
						}
						else
						{
							// If there's no link, the balance must remain the same, only the representative can change
							result.code = result.amount.is_zero () ? lightdag::process_result::progress : lightdag::process_result::balance_mismatch;
						}
					}
				}
				if (result.code == lightdag::process_result::progress)
				{
					result.state_is_send = is_send;
					ledger.store.block_put (transaction, hash, block_a);

					if (!info.rep_block.is_zero ())
					{
						// Move existing representation
						ledger.store.representation_add (transaction, info.rep_block, 0 - info.balance.number ());
					}
					// Add in amount delta
					ledger.store.representation_add (transaction, hash, block_a.hashables.balance.number ());

					if (is_send)
					{
						lightdag::pending_key key (block_a.hashables.link, hash);
						lightdag::pending_info info (block_a.hashables.account, 0 - result.amount.number ());
						ledger.store.pending_put (transaction, key, info);
					}
					else if (!block_a.hashables.link.is_zero ())
					{
						ledger.store.pending_del (transaction, lightdag::pending_key (block_a.hashables.account, block_a.hashables.link));
					}

					ledger.change_latest (transaction, block_a.hashables.account, hash, hash, block_a.hashables.balance, info.block_count + 1, true);
					if (!ledger.store.frontier_get (transaction, info.head).is_zero ())
					{
						ledger.store.frontier_del (transaction, info.head);
					}
					// Frontier table is unnecessary for state blocks and this also prevents old blocks from being inserted on top of state blocks
					result.account = block_a.hashables.account;
				}
			}
		}
	}
}

void ledger_processor::change_block (lightdag::change_block const & block_a)
{
	auto hash (block_a.hash ());
	auto existing (ledger.store.block_exists (transaction, hash));
	result.code = existing ? lightdag::process_result::old : lightdag::process_result::progress; // Have we seen this block before? (Harmless)
	if (result.code == lightdag::process_result::progress)
	{
		auto previous (ledger.store.block_get (transaction, block_a.hashables.previous));
		result.code = previous != nullptr ? lightdag::process_result::progress : lightdag::process_result::gap_previous; // Have we seen the previous block already? (Harmless)
		if (result.code == lightdag::process_result::progress)
		{
			result.code = block_a.valid_predecessor (*previous) ? lightdag::process_result::progress : lightdag::process_result::block_position;
			if (result.code == lightdag::process_result::progress)
			{
				auto account (ledger.store.frontier_get (transaction, block_a.hashables.previous));
				result.code = account.is_zero () ? lightdag::process_result::fork : lightdag::process_result::progress;
				if (result.code == lightdag::process_result::progress)
				{
					lightdag::account_info info;
					auto latest_error (ledger.store.account_get (transaction, account, info));
					assert (!latest_error);
					assert (info.head == block_a.hashables.previous);
					result.code = validate_message (account, hash, block_a.signature) ? lightdag::process_result::bad_signature : lightdag::process_result::progress; // Is this block signed correctly (Malformed)
					if (result.code == lightdag::process_result::progress)
					{
						ledger.store.block_put (transaction, hash, block_a);
						auto balance (ledger.balance (transaction, block_a.hashables.previous));
						ledger.store.representation_add (transaction, hash, balance);
						ledger.store.representation_add (transaction, info.rep_block, 0 - balance);
						ledger.change_latest (transaction, account, hash, hash, info.balance, info.block_count + 1);
						ledger.store.frontier_del (transaction, block_a.hashables.previous);
						ledger.store.frontier_put (transaction, hash, account);
						result.account = account;
						result.amount = 0;
					}
				}
			}
		}
	}
}

void ledger_processor::send_block (lightdag::send_block const & block_a)
{
	auto hash (block_a.hash ());
	auto existing (ledger.store.block_exists (transaction, hash));
	result.code = existing ? lightdag::process_result::old : lightdag::process_result::progress; // Have we seen this block before? (Harmless)
	if (result.code == lightdag::process_result::progress)
	{
		auto previous (ledger.store.block_get (transaction, block_a.hashables.previous));
		result.code = previous != nullptr ? lightdag::process_result::progress : lightdag::process_result::gap_previous; // Have we seen the previous block already? (Harmless)
		if (result.code == lightdag::process_result::progress)
		{
			result.code = block_a.valid_predecessor (*previous) ? lightdag::process_result::progress : lightdag::process_result::block_position;
			if (result.code == lightdag::process_result::progress)
			{
				auto account (ledger.store.frontier_get (transaction, block_a.hashables.previous));
				result.code = account.is_zero () ? lightdag::process_result::fork : lightdag::process_result::progress;
				if (result.code == lightdag::process_result::progress)
				{
					result.code = validate_message (account, hash, block_a.signature) ? lightdag::process_result::bad_signature : lightdag::process_result::progress; // Is this block signed correctly (Malformed)
					if (result.code == lightdag::process_result::progress)
					{
						lightdag::account_info info;
						auto latest_error (ledger.store.account_get (transaction, account, info));
						assert (!latest_error);
						assert (info.head == block_a.hashables.previous);
						result.code = info.balance.number () >= block_a.hashables.balance.number () ? lightdag::process_result::progress : lightdag::process_result::negative_spend; // Is this trying to spend a negative amount (Malicious)
						if (result.code == lightdag::process_result::progress)
						{
							auto amount (info.balance.number () - block_a.hashables.balance.number ());
							ledger.store.representation_add (transaction, info.rep_block, 0 - amount);
							ledger.store.block_put (transaction, hash, block_a);
							ledger.change_latest (transaction, account, hash, info.rep_block, block_a.hashables.balance, info.block_count + 1);
							ledger.store.pending_put (transaction, lightdag::pending_key (block_a.hashables.destination, hash), { account, amount });
							ledger.store.frontier_del (transaction, block_a.hashables.previous);
							ledger.store.frontier_put (transaction, hash, account);
							result.account = account;
							result.amount = amount;
							result.pending_account = block_a.hashables.destination;
						}
					}
				}
			}
		}
	}
}

void ledger_processor::receive_block (lightdag::receive_block const & block_a)
{
	auto hash (block_a.hash ());
	auto existing (ledger.store.block_exists (transaction, hash));
	result.code = existing ? lightdag::process_result::old : lightdag::process_result::progress; // Have we seen this block already?  (Harmless)
	if (result.code == lightdag::process_result::progress)
	{
		auto previous (ledger.store.block_get (transaction, block_a.hashables.previous));
		result.code = previous != nullptr ? lightdag::process_result::progress : lightdag::process_result::gap_previous;
		if (result.code == lightdag::process_result::progress)
		{
			result.code = block_a.valid_predecessor (*previous) ? lightdag::process_result::progress : lightdag::process_result::block_position;
			if (result.code == lightdag::process_result::progress)
			{
				result.code = ledger.store.block_exists (transaction, block_a.hashables.source) ? lightdag::process_result::progress : lightdag::process_result::gap_source; // Have we seen the source block already? (Harmless)
				if (result.code == lightdag::process_result::progress)
				{
					auto account (ledger.store.frontier_get (transaction, block_a.hashables.previous));
					result.code = account.is_zero () ? lightdag::process_result::gap_previous : lightdag::process_result::progress; //Have we seen the previous block? No entries for account at all (Harmless)
					if (result.code == lightdag::process_result::progress)
					{
						result.code = lightdag::validate_message (account, hash, block_a.signature) ? lightdag::process_result::bad_signature : lightdag::process_result::progress; // Is the signature valid (Malformed)
						if (result.code == lightdag::process_result::progress)
						{
							lightdag::account_info info;
							ledger.store.account_get (transaction, account, info);
							result.code = info.head == block_a.hashables.previous ? lightdag::process_result::progress : lightdag::process_result::gap_previous; // Block doesn't immediately follow latest block (Harmless)
							if (result.code == lightdag::process_result::progress)
							{
								lightdag::pending_key key (account, block_a.hashables.source);
								lightdag::pending_info pending;
								result.code = ledger.store.pending_get (transaction, key, pending) ? lightdag::process_result::unreceivable : lightdag::process_result::progress; // Has this source already been received (Malformed)
								if (result.code == lightdag::process_result::progress)
								{
									auto new_balance (info.balance.number () + pending.amount.number ());
									lightdag::account_info source_info;
									auto error (ledger.store.account_get (transaction, pending.source, source_info));
									assert (!error);
									ledger.store.pending_del (transaction, key);
									ledger.store.block_put (transaction, hash, block_a);
									ledger.change_latest (transaction, account, hash, info.rep_block, new_balance, info.block_count + 1);
									ledger.store.representation_add (transaction, info.rep_block, pending.amount.number ());
									ledger.store.frontier_del (transaction, block_a.hashables.previous);
									ledger.store.frontier_put (transaction, hash, account);
									result.account = account;
									result.amount = pending.amount;
								}
							}
						}
					}
					else
					{
						result.code = ledger.store.block_exists (transaction, block_a.hashables.previous) ? lightdag::process_result::fork : lightdag::process_result::gap_previous; // If we have the block but it's not the latest we have a signed fork (Malicious)
					}
				}
			}
		}
	}
}

void ledger_processor::open_block (lightdag::open_block const & block_a)
{
	auto hash (block_a.hash ());
	auto existing (ledger.store.block_exists (transaction, hash));
	result.code = existing ? lightdag::process_result::old : lightdag::process_result::progress; // Have we seen this block already? (Harmless)
	if (result.code == lightdag::process_result::progress)
	{
		auto source_missing (!ledger.store.block_exists (transaction, block_a.hashables.source));
		result.code = source_missing ? lightdag::process_result::gap_source : lightdag::process_result::progress; // Have we seen the source block? (Harmless)
		if (result.code == lightdag::process_result::progress)
		{
			result.code = lightdag::validate_message (block_a.hashables.account, hash, block_a.signature) ? lightdag::process_result::bad_signature : lightdag::process_result::progress; // Is the signature valid (Malformed)
			if (result.code == lightdag::process_result::progress)
			{
				lightdag::account_info info;
				result.code = ledger.store.account_get (transaction, block_a.hashables.account, info) ? lightdag::process_result::progress : lightdag::process_result::fork; // Has this account already been opened? (Malicious)
				if (result.code == lightdag::process_result::progress)
				{
					lightdag::pending_key key (block_a.hashables.account, block_a.hashables.source);
					lightdag::pending_info pending;
					result.code = ledger.store.pending_get (transaction, key, pending) ? lightdag::process_result::unreceivable : lightdag::process_result::progress; // Has this source already been received (Malformed)
					if (result.code == lightdag::process_result::progress)
					{
						result.code = block_a.hashables.account == lightdag::burn_account ? lightdag::process_result::opened_burn_account : lightdag::process_result::progress; // Is it burning 0 account? (Malicious)
						if (result.code == lightdag::process_result::progress)
						{
							lightdag::account_info source_info;
							auto error (ledger.store.account_get (transaction, pending.source, source_info));
							assert (!error);
							ledger.store.pending_del (transaction, key);
							ledger.store.block_put (transaction, hash, block_a);
							ledger.change_latest (transaction, block_a.hashables.account, hash, hash, pending.amount.number (), info.block_count + 1);
							ledger.store.representation_add (transaction, hash, pending.amount.number ());
							ledger.store.frontier_put (transaction, hash, block_a.hashables.account);
							result.account = block_a.hashables.account;
							result.amount = pending.amount;
						}
					}
				}
			}
		}
	}
}

ledger_processor::ledger_processor (lightdag::ledger & ledger_a, MDB_txn * transaction_a) :
ledger (ledger_a),
transaction (transaction_a)
{
}
} // namespace

size_t lightdag::shared_ptr_block_hash::operator() (std::shared_ptr<lightdag::block> const & block_a) const
{
	auto hash (block_a->hash ());
	auto result (static_cast<size_t> (hash.qwords[0]));
	return result;
}

bool lightdag::shared_ptr_block_hash::operator() (std::shared_ptr<lightdag::block> const & lhs, std::shared_ptr<lightdag::block> const & rhs) const
{
	return *lhs == *rhs;
}

lightdag::ledger::ledger (lightdag::block_store & store_a, lightdag::uint128_t const & inactive_supply_a, lightdag::block_hash const & state_block_parse_canary_a, lightdag::block_hash const & state_block_generate_canary_a) :
store (store_a),
inactive_supply (inactive_supply_a),
check_bootstrap_weights (true),
state_block_parse_canary (state_block_parse_canary_a),
state_block_generate_canary (state_block_generate_canary_a)
{
}

// Sum the weights for each vote and return the winning block with its vote tally
std::pair<lightdag::uint128_t, std::shared_ptr<lightdag::block>> lightdag::ledger::winner (MDB_txn * transaction_a, lightdag::votes const & votes_a)
{
	auto tally_l (tally (transaction_a, votes_a));
	auto existing (tally_l.begin ());
	return std::make_pair (existing->first, existing->second);
}

std::map<lightdag::uint128_t, std::shared_ptr<lightdag::block>, std::greater<lightdag::uint128_t>> lightdag::ledger::tally (MDB_txn * transaction_a, lightdag::votes const & votes_a)
{
	std::unordered_map<std::shared_ptr<block>, lightdag::uint128_t, lightdag::shared_ptr_block_hash, lightdag::shared_ptr_block_hash> totals;
	// Construct a map of blocks -> vote total.
	for (auto & i : votes_a.rep_votes)
	{
		auto existing (totals.find (i.second));
		if (existing == totals.end ())
		{
			totals.insert (std::make_pair (i.second, 0));
			existing = totals.find (i.second);
			assert (existing != totals.end ());
		}
		auto weight_l (weight (transaction_a, i.first));
		existing->second += weight_l;
	}
	// Construction a map of vote total -> block in decreasing order.
	std::map<lightdag::uint128_t, std::shared_ptr<lightdag::block>, std::greater<lightdag::uint128_t>> result;
	for (auto & i : totals)
	{
		result[i.second] = i.first;
	}
	return result;
}

// Balance for account containing hash
lightdag::uint128_t lightdag::ledger::balance (MDB_txn * transaction_a, lightdag::block_hash const & hash_a)
{
	balance_visitor visitor (transaction_a, store);
	visitor.compute (hash_a);
	return visitor.result;
}

// Balance for an account by account number
lightdag::uint128_t lightdag::ledger::account_balance (MDB_txn * transaction_a, lightdag::account const & account_a)
{
	lightdag::uint128_t result (0);
	lightdag::account_info info;
	auto none (store.account_get (transaction_a, account_a, info));
	if (!none)
	{
		result = info.balance.number ();
	}
	return result;
}

lightdag::uint128_t lightdag::ledger::account_pending (MDB_txn * transaction_a, lightdag::account const & account_a)
{
	lightdag::uint128_t result (0);
	lightdag::account end (account_a.number () + 1);
	for (auto i (store.pending_begin (transaction_a, lightdag::pending_key (account_a, 0))), n (store.pending_begin (transaction_a, lightdag::pending_key (end, 0))); i != n; ++i)
	{
		lightdag::pending_info info (i->second);
		result += info.amount.number ();
	}
	return result;
}

lightdag::process_return lightdag::ledger::process (MDB_txn * transaction_a, lightdag::block const & block_a)
{
	ledger_processor processor (*this, transaction_a);
	block_a.visit (processor);
	return processor.result;
}

// Money supply for heuristically calculating vote percentages
lightdag::uint128_t lightdag::ledger::supply (MDB_txn * transaction_a)
{
	auto unallocated (account_balance (transaction_a, lightdag::genesis_account));
	auto burned (account_pending (transaction_a, 0));
	auto absolute_supply (lightdag::genesis_amount - unallocated - burned);
	auto adjusted_supply (absolute_supply - inactive_supply);
	return adjusted_supply <= absolute_supply ? adjusted_supply : 0;
}

lightdag::block_hash lightdag::ledger::representative (MDB_txn * transaction_a, lightdag::block_hash const & hash_a)
{
	auto result (representative_calculated (transaction_a, hash_a));
	assert (result.is_zero () || store.block_exists (transaction_a, result));
	return result;
}

lightdag::block_hash lightdag::ledger::representative_calculated (MDB_txn * transaction_a, lightdag::block_hash const & hash_a)
{
	representative_visitor visitor (transaction_a, store);
	visitor.compute (hash_a);
	return visitor.result;
}

bool lightdag::ledger::block_exists (lightdag::block_hash const & hash_a)
{
	lightdag::transaction transaction (store.environment, nullptr, false);
	auto result (store.block_exists (transaction, hash_a));
	return result;
}

std::string lightdag::ledger::block_text (char const * hash_a)
{
	return block_text (lightdag::block_hash (hash_a));
}

std::string lightdag::ledger::block_text (lightdag::block_hash const & hash_a)
{
	std::string result;
	lightdag::transaction transaction (store.environment, nullptr, false);
	auto block (store.block_get (transaction, hash_a));
	if (block != nullptr)
	{
		block->serialize_json (result);
	}
	return result;
}

bool lightdag::ledger::is_send (MDB_txn * transaction_a, lightdag::state_block const & block_a)
{
	bool result (false);
	lightdag::block_hash previous (block_a.hashables.previous);
	if (!previous.is_zero ())
	{
		if (block_a.hashables.balance < balance (transaction_a, previous))
		{
			result = true;
		}
	}
	return result;
}

lightdag::block_hash lightdag::ledger::block_destination (MDB_txn * transaction_a, lightdag::block const & block_a)
{
	lightdag::block_hash result (0);
	lightdag::send_block const * send_block (dynamic_cast<lightdag::send_block const *> (&block_a));
	lightdag::state_block const * state_block (dynamic_cast<lightdag::state_block const *> (&block_a));
	if (send_block != nullptr)
	{
		result = send_block->hashables.destination;
	}
	else if (state_block != nullptr && is_send (transaction_a, *state_block))
	{
		result = state_block->hashables.link;
	}
	return result;
}

lightdag::block_hash lightdag::ledger::block_source (MDB_txn * transaction_a, lightdag::block const & block_a)
{
	// If block_a.source () is nonzero, then we have our source.
	// However, universal blocks will always return zero.
	lightdag::block_hash result (block_a.source ());
	lightdag::state_block const * state_block (dynamic_cast<lightdag::state_block const *> (&block_a));
	if (state_block != nullptr && !is_send (transaction_a, *state_block))
	{
		result = state_block->hashables.link;
	}
	return result;
}

// Vote weight of an account
lightdag::uint128_t lightdag::ledger::weight (MDB_txn * transaction_a, lightdag::account const & account_a)
{
	if (check_bootstrap_weights.load ())
	{
		auto blocks = store.block_count (transaction_a);
		if (blocks.sum () < bootstrap_weight_max_blocks)
		{
			auto weight = bootstrap_weights.find (account_a);
			if (weight != bootstrap_weights.end ())
			{
				return weight->second;
			}
		}
		else
		{
			check_bootstrap_weights = false;
		}
	}
	return store.representation_get (transaction_a, account_a);
}

// Rollback blocks until `block_a' doesn't exist
void lightdag::ledger::rollback (MDB_txn * transaction_a, lightdag::block_hash const & block_a)
{
	assert (store.block_exists (transaction_a, block_a));
	auto account_l (account (transaction_a, block_a));
	rollback_visitor rollback (transaction_a, *this);
	lightdag::account_info info;
	while (store.block_exists (transaction_a, block_a))
	{
		auto latest_error (store.account_get (transaction_a, account_l, info));
		assert (!latest_error);
		auto block (store.block_get (transaction_a, info.head));
		block->visit (rollback);
	}
}

// Return account containing hash
lightdag::account lightdag::ledger::account (MDB_txn * transaction_a, lightdag::block_hash const & hash_a)
{
	lightdag::account result;
	auto hash (hash_a);
	lightdag::block_hash successor (1);
	lightdag::block_info block_info;
	std::unique_ptr<lightdag::block> block (store.block_get (transaction_a, hash));
	while (!successor.is_zero () && block->type () != lightdag::block_type::state && store.block_info_get (transaction_a, successor, block_info))
	{
		successor = store.block_successor (transaction_a, hash);
		if (!successor.is_zero ())
		{
			hash = successor;
			block = store.block_get (transaction_a, hash);
		}
	}
	if (block->type () == lightdag::block_type::state)
	{
		auto state_block (dynamic_cast<lightdag::state_block *> (block.get ()));
		result = state_block->hashables.account;
	}
	else if (successor.is_zero ())
	{
		result = store.frontier_get (transaction_a, hash);
	}
	else
	{
		result = block_info.account;
	}
	assert (!result.is_zero ());
	return result;
}

// Return amount decrease or increase for block
lightdag::uint128_t lightdag::ledger::amount (MDB_txn * transaction_a, lightdag::block_hash const & hash_a)
{
	amount_visitor amount (transaction_a, store);
	amount.compute (hash_a);
	return amount.result;
}

// Return latest block for account
lightdag::block_hash lightdag::ledger::latest (MDB_txn * transaction_a, lightdag::account const & account_a)
{
	lightdag::account_info info;
	auto latest_error (store.account_get (transaction_a, account_a, info));
	return latest_error ? 0 : info.head;
}

// Return latest root for account, account number of there are no blocks for this account.
lightdag::block_hash lightdag::ledger::latest_root (MDB_txn * transaction_a, lightdag::account const & account_a)
{
	lightdag::account_info info;
	auto latest_error (store.account_get (transaction_a, account_a, info));
	lightdag::block_hash result;
	if (latest_error)
	{
		result = account_a;
	}
	else
	{
		result = info.head;
	}
	return result;
}

lightdag::checksum lightdag::ledger::checksum (MDB_txn * transaction_a, lightdag::account const & begin_a, lightdag::account const & end_a)
{
	lightdag::checksum result;
	auto error (store.checksum_get (transaction_a, 0, 0, result));
	assert (!error);
	return result;
}

void lightdag::ledger::dump_account_chain (lightdag::account const & account_a)
{
	lightdag::transaction transaction (store.environment, nullptr, false);
	auto hash (latest (transaction, account_a));
	while (!hash.is_zero ())
	{
		auto block (store.block_get (transaction, hash));
		assert (block != nullptr);
		std::cerr << hash.to_string () << std::endl;
		hash = block->previous ();
	}
}

bool lightdag::ledger::state_block_parsing_enabled (MDB_txn * transaction_a)
{
	return store.block_exists (transaction_a, state_block_parse_canary);
}

bool lightdag::ledger::state_block_generation_enabled (MDB_txn * transaction_a)
{
	return state_block_parsing_enabled (transaction_a) && store.block_exists (transaction_a, state_block_generate_canary);
}

void lightdag::ledger::checksum_update (MDB_txn * transaction_a, lightdag::block_hash const & hash_a)
{
	lightdag::checksum value;
	auto error (store.checksum_get (transaction_a, 0, 0, value));
	assert (!error);
	value ^= hash_a;
	store.checksum_put (transaction_a, 0, 0, value);
}

void lightdag::ledger::change_latest (MDB_txn * transaction_a, lightdag::account const & account_a, lightdag::block_hash const & hash_a, lightdag::block_hash const & rep_block_a, lightdag::amount const & balance_a, uint64_t block_count_a, bool is_state)
{
	lightdag::account_info info;
	auto exists (!store.account_get (transaction_a, account_a, info));
	if (exists)
	{
		checksum_update (transaction_a, info.head);
	}
	else
	{
		assert (store.block_get (transaction_a, hash_a)->previous ().is_zero ());
		info.open_block = hash_a;
	}
	if (!hash_a.is_zero ())
	{
		info.head = hash_a;
		info.rep_block = rep_block_a;
		info.balance = balance_a;
		info.modified = lightdag::seconds_since_epoch ();
		info.block_count = block_count_a;
		store.account_put (transaction_a, account_a, info);
		if (!(block_count_a % store.block_info_max) && !is_state)
		{
			lightdag::block_info block_info;
			block_info.account = account_a;
			block_info.balance = balance_a;
			store.block_info_put (transaction_a, hash_a, block_info);
		}
		checksum_update (transaction_a, hash_a);
	}
	else
	{
		store.account_del (transaction_a, account_a);
	}
}

std::unique_ptr<lightdag::block> lightdag::ledger::successor (MDB_txn * transaction_a, lightdag::block_hash const & block_a)
{
	assert (store.account_exists (transaction_a, block_a) || store.block_exists (transaction_a, block_a));
	assert (store.account_exists (transaction_a, block_a) || latest (transaction_a, account (transaction_a, block_a)) != block_a);
	lightdag::block_hash successor;
	if (store.account_exists (transaction_a, block_a))
	{
		lightdag::account_info info;
		auto error (store.account_get (transaction_a, block_a, info));
		assert (!error);
		successor = info.open_block;
	}
	else
	{
		successor = store.block_successor (transaction_a, block_a);
	}
	assert (!successor.is_zero ());
	auto result (store.block_get (transaction_a, successor));
	assert (result != nullptr);
	return result;
}

std::unique_ptr<lightdag::block> lightdag::ledger::forked_block (MDB_txn * transaction_a, lightdag::block const & block_a)
{
	assert (!store.block_exists (transaction_a, block_a.hash ()));
	auto root (block_a.root ());
	assert (store.block_exists (transaction_a, root) || store.account_exists (transaction_a, root));
	std::unique_ptr<lightdag::block> result (store.block_get (transaction_a, store.block_successor (transaction_a, root)));
	if (result == nullptr)
	{
		lightdag::account_info info;
		auto error (store.account_get (transaction_a, root, info));
		assert (!error);
		result = store.block_get (transaction_a, info.open_block);
		assert (result != nullptr);
	}
	return result;
}
