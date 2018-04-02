#pragma once

#include <lightdag/node/node.hpp>

namespace lightdag
{
class system
{
public:
	system (uint16_t, size_t);
	~system ();
	void generate_activity (lightdag::node &, std::vector<lightdag::account> &);
	void generate_mass_activity (uint32_t, lightdag::node &);
	void generate_usage_traffic (uint32_t, uint32_t, size_t);
	void generate_usage_traffic (uint32_t, uint32_t);
	lightdag::account get_random_account (std::vector<lightdag::account> &);
	lightdag::uint128_t get_random_amount (MDB_txn *, lightdag::node &, lightdag::account const &);
	void generate_rollback (lightdag::node &, std::vector<lightdag::account> &);
	void generate_change_known (lightdag::node &, std::vector<lightdag::account> &);
	void generate_change_unknown (lightdag::node &, std::vector<lightdag::account> &);
	void generate_receive (lightdag::node &);
	void generate_send_new (lightdag::node &, std::vector<lightdag::account> &);
	void generate_send_existing (lightdag::node &, std::vector<lightdag::account> &);
	std::shared_ptr<lightdag::wallet> wallet (size_t);
	lightdag::account account (MDB_txn *, size_t);
	void poll ();
	void stop ();
	boost::asio::io_service service;
	lightdag::alarm alarm;
	std::vector<std::shared_ptr<lightdag::node>> nodes;
	lightdag::logging logging;
	lightdag::work_pool work;
};
class landing_store
{
public:
	landing_store ();
	landing_store (lightdag::account const &, lightdag::account const &, uint64_t, uint64_t);
	landing_store (bool &, std::istream &);
	lightdag::account source;
	lightdag::account destination;
	uint64_t start;
	uint64_t last;
	bool deserialize (std::istream &);
	void serialize (std::ostream &) const;
	bool operator== (lightdag::landing_store const &) const;
};
class landing
{
public:
	landing (lightdag::node &, std::shared_ptr<lightdag::wallet>, lightdag::landing_store &, boost::filesystem::path const &);
	void write_store ();
	lightdag::uint128_t distribution_amount (uint64_t);
	void distribute_one ();
	void distribute_ongoing ();
	boost::filesystem::path path;
	lightdag::landing_store & store;
	std::shared_ptr<lightdag::wallet> wallet;
	lightdag::node & node;
	static int constexpr interval_exponent = 10;
	static std::chrono::seconds constexpr distribution_interval = std::chrono::seconds (1 << interval_exponent); // 1024 seconds
	static std::chrono::seconds constexpr sleep_seconds = std::chrono::seconds (7);
};
}
