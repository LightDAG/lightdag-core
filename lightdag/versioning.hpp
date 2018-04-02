#pragma once

#include <lightdag/lib/blocks.hpp>
#include <lightdag/node/utility.hpp>

namespace lightdag
{
class account_info_v1
{
public:
	account_info_v1 ();
	account_info_v1 (MDB_val const &);
	account_info_v1 (lightdag::account_info_v1 const &) = default;
	account_info_v1 (lightdag::block_hash const &, lightdag::block_hash const &, lightdag::amount const &, uint64_t);
	void serialize (lightdag::stream &) const;
	bool deserialize (lightdag::stream &);
	lightdag::mdb_val val () const;
	lightdag::block_hash head;
	lightdag::block_hash rep_block;
	lightdag::amount balance;
	uint64_t modified;
};
class pending_info_v3
{
public:
	pending_info_v3 ();
	pending_info_v3 (MDB_val const &);
	pending_info_v3 (lightdag::account const &, lightdag::amount const &, lightdag::account const &);
	void serialize (lightdag::stream &) const;
	bool deserialize (lightdag::stream &);
	bool operator== (lightdag::pending_info_v3 const &) const;
	lightdag::mdb_val val () const;
	lightdag::account source;
	lightdag::amount amount;
	lightdag::account destination;
};
// Latest information about an account
class account_info_v5
{
public:
	account_info_v5 ();
	account_info_v5 (MDB_val const &);
	account_info_v5 (lightdag::account_info_v5 const &) = default;
	account_info_v5 (lightdag::block_hash const &, lightdag::block_hash const &, lightdag::block_hash const &, lightdag::amount const &, uint64_t);
	void serialize (lightdag::stream &) const;
	bool deserialize (lightdag::stream &);
	lightdag::mdb_val val () const;
	lightdag::block_hash head;
	lightdag::block_hash rep_block;
	lightdag::block_hash open_block;
	lightdag::amount balance;
	uint64_t modified;
};
}
