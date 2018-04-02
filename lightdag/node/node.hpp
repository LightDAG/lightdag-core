#pragma once

#include <lightdag/ledger.hpp>
#include <lightdag/lib/work.hpp>
#include <lightdag/node/bootstrap.hpp>
#include <lightdag/node/wallet.hpp>

#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_set>

#include <boost/asio.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/log/trivial.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/random_access_index.hpp>
#include <boost/multi_index_container.hpp>

#include <miniupnpc.h>

namespace boost
{
namespace program_options
{
	class options_description;
	class variables_map;
}
}

namespace lightdag
{
class node;
class election : public std::enable_shared_from_this<lightdag::election>
{
	std::function<void(std::shared_ptr<lightdag::block>, bool)> confirmation_action;
	void confirm_once (MDB_txn *);

public:
	election (MDB_txn *, lightdag::node &, std::shared_ptr<lightdag::block>, std::function<void(std::shared_ptr<lightdag::block>, bool)> const &);
	bool vote (std::shared_ptr<lightdag::vote>);
	// Check if we have vote quorum
	bool have_quorum (MDB_txn *);
	// Tell the network our view of the winner
	void broadcast_winner ();
	// Change our winner to agree with the network
	void compute_rep_votes (MDB_txn *);
	// Confirmation method 1, uncontested quorum
	void confirm_if_quorum (MDB_txn *);
	// Confirmation method 2, settling time
	void confirm_cutoff (MDB_txn *);
	lightdag::uint128_t quorum_threshold (MDB_txn *, lightdag::ledger &);
	lightdag::uint128_t minimum_threshold (MDB_txn *, lightdag::ledger &);
	lightdag::votes votes;
	lightdag::node & node;
	std::unordered_map<lightdag::account, std::pair<std::chrono::steady_clock::time_point, uint64_t>> last_votes;
	std::shared_ptr<lightdag::block> last_winner;
	std::atomic_flag confirmed;
};
class conflict_info
{
public:
	lightdag::block_hash root;
	std::shared_ptr<lightdag::election> election;
	// Number of announcements in a row for this fork
	unsigned announcements;
};
// Core class for determining consensus
// Holds all active blocks i.e. recently added blocks that need confirmation
class active_transactions
{
public:
	active_transactions (lightdag::node &);
	// Start an election for a block
	// Call action with confirmed block, may be different than what we started with
	bool start (MDB_txn *, std::shared_ptr<lightdag::block>, std::function<void(std::shared_ptr<lightdag::block>, bool)> const & = [](std::shared_ptr<lightdag::block>, bool) {});
	// If this returns true, the vote is a replay
	// If this returns false, the vote may or may not be a replay
	bool vote (std::shared_ptr<lightdag::vote>);
	// Is the root of this block in the roots container
	bool active (lightdag::block const &);
	void announce_votes ();
	std::deque<std::shared_ptr<lightdag::block>> list_blocks ();
	void stop ();
	boost::multi_index_container<
	lightdag::conflict_info,
	boost::multi_index::indexed_by<
	boost::multi_index::ordered_unique<boost::multi_index::member<lightdag::conflict_info, lightdag::block_hash, &lightdag::conflict_info::root>>>>
	roots;
	lightdag::node & node;
	std::mutex mutex;
	// Maximum number of conflicts to vote on per interval, lowest root hash first
	static unsigned constexpr announcements_per_interval = 32;
	// After this many successive vote announcements, block is confirmed
	static unsigned constexpr contiguous_announcements = 4;
	static unsigned constexpr announce_interval_ms = (lightdag::lightdag_network == lightdag::lightdag_networks::lightdag_test_network) ? 10 : 16000;
};
class operation
{
public:
	bool operator> (lightdag::operation const &) const;
	std::chrono::steady_clock::time_point wakeup;
	std::function<void()> function;
};
class alarm
{
public:
	alarm (boost::asio::io_service &);
	~alarm ();
	void add (std::chrono::steady_clock::time_point const &, std::function<void()> const &);
	void run ();
	boost::asio::io_service & service;
	std::mutex mutex;
	std::condition_variable condition;
	std::priority_queue<operation, std::vector<operation>, std::greater<operation>> operations;
	std::thread thread;
};
class gap_information
{
public:
	std::chrono::steady_clock::time_point arrival;
	lightdag::block_hash hash;
	std::unique_ptr<lightdag::votes> votes;
};
class gap_cache
{
public:
	gap_cache (lightdag::node &);
	void add (MDB_txn *, std::shared_ptr<lightdag::block>);
	void vote (std::shared_ptr<lightdag::vote>);
	lightdag::uint128_t bootstrap_threshold (MDB_txn *);
	void purge_old ();
	boost::multi_index_container<
	lightdag::gap_information,
	boost::multi_index::indexed_by<
	boost::multi_index::ordered_non_unique<boost::multi_index::member<gap_information, std::chrono::steady_clock::time_point, &gap_information::arrival>>,
	boost::multi_index::hashed_unique<boost::multi_index::member<gap_information, lightdag::block_hash, &gap_information::hash>>>>
	blocks;
	size_t const max = 256;
	std::mutex mutex;
	lightdag::node & node;
};
class work_pool;
class peer_information
{
public:
	peer_information (lightdag::endpoint const &, unsigned);
	peer_information (lightdag::endpoint const &, std::chrono::steady_clock::time_point const &, std::chrono::steady_clock::time_point const &);
	lightdag::endpoint endpoint;
	std::chrono::steady_clock::time_point last_contact;
	std::chrono::steady_clock::time_point last_attempt;
	std::chrono::steady_clock::time_point last_bootstrap_attempt;
	std::chrono::steady_clock::time_point last_rep_request;
	std::chrono::steady_clock::time_point last_rep_response;
	lightdag::amount rep_weight;
	unsigned network_version;
};
class peer_attempt
{
public:
	lightdag::endpoint endpoint;
	std::chrono::steady_clock::time_point last_attempt;
};
class peer_container
{
public:
	peer_container (lightdag::endpoint const &);
	// We were contacted by endpoint, update peers
	void contacted (lightdag::endpoint const &, unsigned);
	// Unassigned, reserved, self
	bool not_a_peer (lightdag::endpoint const &);
	// Returns true if peer was already known
	bool known_peer (lightdag::endpoint const &);
	// Notify of peer we received from
	bool insert (lightdag::endpoint const &, unsigned);
	std::unordered_set<lightdag::endpoint> random_set (size_t);
	void random_fill (std::array<lightdag::endpoint, 8> &);
	// Request a list of the top known representatives
	std::vector<peer_information> representatives (size_t);
	// List of all peers
	std::vector<lightdag::endpoint> list ();
	std::map<lightdag::endpoint, unsigned> list_version ();
	// A list of random peers with size the square root of total peer count
	std::vector<lightdag::endpoint> list_sqrt ();
	// Get the next peer for attempting bootstrap
	lightdag::endpoint bootstrap_peer ();
	// Purge any peer where last_contact < time_point and return what was left
	std::vector<lightdag::peer_information> purge_list (std::chrono::steady_clock::time_point const &);
	std::vector<lightdag::endpoint> rep_crawl ();
	bool rep_response (lightdag::endpoint const &, lightdag::amount const &);
	void rep_request (lightdag::endpoint const &);
	// Should we reach out to this endpoint with a keepalive message
	bool reachout (lightdag::endpoint const &);
	size_t size ();
	size_t size_sqrt ();
	bool empty ();
	std::mutex mutex;
	lightdag::endpoint self;
	boost::multi_index_container<
	peer_information,
	boost::multi_index::indexed_by<
	boost::multi_index::hashed_unique<boost::multi_index::member<peer_information, lightdag::endpoint, &peer_information::endpoint>>,
	boost::multi_index::ordered_non_unique<boost::multi_index::member<peer_information, std::chrono::steady_clock::time_point, &peer_information::last_contact>>,
	boost::multi_index::ordered_non_unique<boost::multi_index::member<peer_information, std::chrono::steady_clock::time_point, &peer_information::last_attempt>, std::greater<std::chrono::steady_clock::time_point>>,
	boost::multi_index::random_access<>,
	boost::multi_index::ordered_non_unique<boost::multi_index::member<peer_information, std::chrono::steady_clock::time_point, &peer_information::last_bootstrap_attempt>>,
	boost::multi_index::ordered_non_unique<boost::multi_index::member<peer_information, std::chrono::steady_clock::time_point, &peer_information::last_rep_request>>,
	boost::multi_index::ordered_non_unique<boost::multi_index::member<peer_information, lightdag::amount, &peer_information::rep_weight>, std::greater<lightdag::amount>>>>
	peers;
	boost::multi_index_container<
	peer_attempt,
	boost::multi_index::indexed_by<
	boost::multi_index::hashed_unique<boost::multi_index::member<peer_attempt, lightdag::endpoint, &peer_attempt::endpoint>>,
	boost::multi_index::ordered_non_unique<boost::multi_index::member<peer_attempt, std::chrono::steady_clock::time_point, &peer_attempt::last_attempt>>>>
	attempts;
	// Called when a new peer is observed
	std::function<void(lightdag::endpoint const &)> peer_observer;
	std::function<void()> disconnect_observer;
	// Number of peers to crawl for being a rep every period
	static size_t constexpr peers_per_crawl = 8;
};
class send_info
{
public:
	uint8_t const * data;
	size_t size;
	lightdag::endpoint endpoint;
	std::function<void(boost::system::error_code const &, size_t)> callback;
};
class mapping_protocol
{
public:
	char const * name;
	int remaining;
	boost::asio::ip::address_v4 external_address;
	uint16_t external_port;
};
// These APIs aren't easy to understand so comments are verbose
class port_mapping
{
public:
	port_mapping (lightdag::node &);
	void start ();
	void stop ();
	void refresh_devices ();
	// Refresh when the lease ends
	void refresh_mapping ();
	// Refresh occasionally in case router loses mapping
	void check_mapping_loop ();
	int check_mapping ();
	bool has_address ();
	std::mutex mutex;
	lightdag::node & node;
	UPNPDev * devices; // List of all UPnP devices
	UPNPUrls urls; // Something for UPnP
	IGDdatas data; // Some other UPnP thing
	// Primes so they infrequently happen at the same time
	static int constexpr mapping_timeout = lightdag::lightdag_network == lightdag::lightdag_networks::lightdag_test_network ? 53 : 3593;
	static int constexpr check_timeout = lightdag::lightdag_network == lightdag::lightdag_networks::lightdag_test_network ? 17 : 53;
	boost::asio::ip::address_v4 address;
	std::array<mapping_protocol, 2> protocols;
	uint64_t check_count;
	bool on;
};
class message_statistics
{
public:
	message_statistics ();
	std::atomic<uint64_t> keepalive;
	std::atomic<uint64_t> publish;
	std::atomic<uint64_t> confirm_req;
	std::atomic<uint64_t> confirm_ack;
};
class block_arrival_info
{
public:
	std::chrono::steady_clock::time_point arrival;
	lightdag::block_hash hash;
};
// This class tracks blocks that are probably live because they arrived in a UDP packet
// This gives a fairly reliable way to differentiate between blocks being inserted via bootstrap or new, live blocks.
class block_arrival
{
public:
	void add (lightdag::block_hash const &);
	bool recent (lightdag::block_hash const &);
	boost::multi_index_container<
	lightdag::block_arrival_info,
	boost::multi_index::indexed_by<
	boost::multi_index::ordered_non_unique<boost::multi_index::member<lightdag::block_arrival_info, std::chrono::steady_clock::time_point, &lightdag::block_arrival_info::arrival>>,
	boost::multi_index::hashed_unique<boost::multi_index::member<lightdag::block_arrival_info, lightdag::block_hash, &lightdag::block_arrival_info::hash>>>>
	arrival;
	std::mutex mutex;
};
class network
{
public:
	network (lightdag::node &, uint16_t);
	void receive ();
	void stop ();
	void receive_action (boost::system::error_code const &, size_t);
	void rpc_action (boost::system::error_code const &, size_t);
	void rebroadcast_reps (std::shared_ptr<lightdag::block>);
	void republish_vote (std::shared_ptr<lightdag::vote>);
	void republish_block (MDB_txn *, std::shared_ptr<lightdag::block>);
	void republish (lightdag::block_hash const &, std::shared_ptr<std::vector<uint8_t>>, lightdag::endpoint);
	void publish_broadcast (std::vector<lightdag::peer_information> &, std::unique_ptr<lightdag::block>);
	void confirm_send (lightdag::confirm_ack const &, std::shared_ptr<std::vector<uint8_t>>, lightdag::endpoint const &);
	void merge_peers (std::array<lightdag::endpoint, 8> const &);
	void send_keepalive (lightdag::endpoint const &);
	void broadcast_confirm_req (std::shared_ptr<lightdag::block>);
	void send_confirm_req (lightdag::endpoint const &, std::shared_ptr<lightdag::block>);
	void send_buffer (uint8_t const *, size_t, lightdag::endpoint const &, std::function<void(boost::system::error_code const &, size_t)>);
	lightdag::endpoint endpoint ();
	lightdag::endpoint remote;
	std::array<uint8_t, 512> buffer;
	boost::asio::ip::udp::socket socket;
	std::mutex socket_mutex;
	boost::asio::ip::udp::resolver resolver;
	lightdag::node & node;
	uint64_t bad_sender_count;
	bool on;
	uint64_t insufficient_work_count;
	uint64_t error_count;
	lightdag::message_statistics incoming;
	lightdag::message_statistics outgoing;
    static uint16_t const node_port = lightdag::lightdag_network == lightdag::lightdag_networks::lightdag_live_network ? 7075 : 54000;
};
class logging
{
public:
	logging ();
	void serialize_json (boost::property_tree::ptree &) const;
	bool deserialize_json (bool &, boost::property_tree::ptree &);
	bool upgrade_json (unsigned, boost::property_tree::ptree &);
	bool ledger_logging () const;
	bool ledger_duplicate_logging () const;
	bool vote_logging () const;
	bool network_logging () const;
	bool network_message_logging () const;
	bool network_publish_logging () const;
	bool network_packet_logging () const;
	bool network_keepalive_logging () const;
	bool node_lifetime_tracing () const;
	bool insufficient_work_logging () const;
	bool log_rpc () const;
	bool bulk_pull_logging () const;
	bool callback_logging () const;
	bool work_generation_time () const;
	bool log_to_cerr () const;
	void init (boost::filesystem::path const &);

	bool ledger_logging_value;
	bool ledger_duplicate_logging_value;
	bool vote_logging_value;
	bool network_logging_value;
	bool network_message_logging_value;
	bool network_publish_logging_value;
	bool network_packet_logging_value;
	bool network_keepalive_logging_value;
	bool node_lifetime_tracing_value;
	bool insufficient_work_logging_value;
	bool log_rpc_value;
	bool bulk_pull_logging_value;
	bool work_generation_time_value;
	bool log_to_cerr_value;
	bool flush;
	uintmax_t max_size;
	uintmax_t rotation_size;
	boost::log::sources::logger_mt log;
};
class node_init
{
public:
	node_init ();
	bool error ();
	bool block_store_init;
	bool wallet_init;
};
class node_config
{
public:
	node_config ();
	node_config (uint16_t, lightdag::logging const &);
	void serialize_json (boost::property_tree::ptree &) const;
	bool deserialize_json (bool &, boost::property_tree::ptree &);
	bool upgrade_json (unsigned, boost::property_tree::ptree &);
	lightdag::account random_representative ();
	uint16_t peering_port;
	lightdag::logging logging;
	std::vector<std::pair<boost::asio::ip::address, uint16_t>> work_peers;
	std::vector<std::string> preconfigured_peers;
	std::vector<lightdag::account> preconfigured_representatives;
	unsigned bootstrap_fraction_numerator;
	lightdag::amount receive_minimum;
	lightdag::amount inactive_supply;
	unsigned password_fanout;
	unsigned io_threads;
	unsigned work_threads;
	bool enable_voting;
	unsigned bootstrap_connections;
	unsigned bootstrap_connections_max;
	std::string callback_address;
	uint16_t callback_port;
	std::string callback_target;
	int lmdb_max_dbs;
	lightdag::block_hash state_block_parse_canary;
	lightdag::block_hash state_block_generate_canary;
	static std::chrono::seconds constexpr keepalive_period = std::chrono::seconds (60);
	static std::chrono::seconds constexpr keepalive_cutoff = keepalive_period * 5;
	static std::chrono::minutes constexpr wallet_backup_interval = std::chrono::minutes (5);
};
class node_observers
{
public:
	lightdag::observer_set<std::shared_ptr<lightdag::block>, lightdag::process_return const &> blocks;
	lightdag::observer_set<bool> wallet;
	lightdag::observer_set<std::shared_ptr<lightdag::vote>, lightdag::endpoint const &> vote;
	lightdag::observer_set<lightdag::account const &, bool> account_balance;
	lightdag::observer_set<lightdag::endpoint const &> endpoint;
	lightdag::observer_set<> disconnect;
	lightdag::observer_set<> started;
};
class vote_processor
{
public:
	vote_processor (lightdag::node &);
	lightdag::vote_result vote (std::shared_ptr<lightdag::vote>, lightdag::endpoint);
	lightdag::node & node;
};
// The network is crawled for representatives by occasionally sending a unicast confirm_req for a specific block and watching to see if it's acknowledged with a vote.
class rep_crawler
{
public:
	void add (lightdag::block_hash const &);
	void remove (lightdag::block_hash const &);
	bool exists (lightdag::block_hash const &);
	std::mutex mutex;
	std::unordered_set<lightdag::block_hash> active;
};
class block_processor_item
{
public:
	block_processor_item (std::shared_ptr<lightdag::block>);
	block_processor_item (std::shared_ptr<lightdag::block>, bool);
	std::shared_ptr<lightdag::block> block;
	bool force;
};
// Processing blocks is a potentially long IO operation
// This class isolates block insertion from other operations like servicing network operations
class block_processor
{
public:
	block_processor (lightdag::node &);
	~block_processor ();
	void stop ();
	void flush ();
	void add (lightdag::block_processor_item const &);
	void process_receive_many (lightdag::block_processor_item const &);
	void process_receive_many (std::deque<lightdag::block_processor_item> &);
	lightdag::process_return process_receive_one (MDB_txn *, std::shared_ptr<lightdag::block>);
	void process_blocks ();

private:
	bool stopped;
	bool idle;
	std::deque<lightdag::block_processor_item> blocks;
	std::mutex mutex;
	std::condition_variable condition;
	lightdag::node & node;
};
class node : public std::enable_shared_from_this<lightdag::node>
{
public:
	node (lightdag::node_init &, boost::asio::io_service &, uint16_t, boost::filesystem::path const &, lightdag::alarm &, lightdag::logging const &, lightdag::work_pool &);
	node (lightdag::node_init &, boost::asio::io_service &, boost::filesystem::path const &, lightdag::alarm &, lightdag::node_config const &, lightdag::work_pool &);
	~node ();
	template <typename T>
	void background (T action_a)
	{
		alarm.service.post (action_a);
	}
	void send_keepalive (lightdag::endpoint const &);
	bool copy_with_compaction (boost::filesystem::path const &);
	void keepalive (std::string const &, uint16_t);
	void start ();
	void stop ();
	std::shared_ptr<lightdag::node> shared ();
	int store_version ();
	void process_confirmed (std::shared_ptr<lightdag::block>);
	void process_message (lightdag::message &, lightdag::endpoint const &);
	void process_active (std::shared_ptr<lightdag::block>);
	lightdag::process_return process (lightdag::block const &);
	void keepalive_preconfigured (std::vector<std::string> const &);
	lightdag::block_hash latest (lightdag::account const &);
	lightdag::uint128_t balance (lightdag::account const &);
	std::unique_ptr<lightdag::block> block (lightdag::block_hash const &);
	std::pair<lightdag::uint128_t, lightdag::uint128_t> balance_pending (lightdag::account const &);
	lightdag::uint128_t weight (lightdag::account const &);
	lightdag::account representative (lightdag::account const &);
	void ongoing_keepalive ();
	void ongoing_rep_crawl ();
	void ongoing_bootstrap ();
	void ongoing_store_flush ();
	void backup_wallet ();
	int price (lightdag::uint128_t const &, int);
	void generate_work (lightdag::block &);
	uint64_t generate_work (lightdag::uint256_union const &);
	void generate_work (lightdag::uint256_union const &, std::function<void(uint64_t)>);
	void add_initial_peers ();
	boost::asio::io_service & service;
	lightdag::node_config config;
	lightdag::alarm & alarm;
	lightdag::work_pool & work;
	boost::log::sources::logger_mt log;
	lightdag::block_store store;
	lightdag::gap_cache gap_cache;
	lightdag::ledger ledger;
	lightdag::active_transactions active;
	lightdag::network network;
	lightdag::bootstrap_initiator bootstrap_initiator;
	lightdag::bootstrap_listener bootstrap;
	lightdag::peer_container peers;
	boost::filesystem::path application_path;
	lightdag::node_observers observers;
	lightdag::wallets wallets;
	lightdag::port_mapping port_mapping;
	lightdag::vote_processor vote_processor;
	lightdag::rep_crawler rep_crawler;
	unsigned warmed_up;
	lightdag::block_processor block_processor;
	std::thread block_processor_thread;
	lightdag::block_arrival block_arrival;
	static double constexpr price_max = 16.0;
	static double constexpr free_cutoff = 1024.0;
	static std::chrono::seconds constexpr period = std::chrono::seconds (60);
	static std::chrono::seconds constexpr cutoff = period * 5;
	static std::chrono::minutes constexpr backup_interval = std::chrono::minutes (5);
};
class thread_runner
{
public:
	thread_runner (boost::asio::io_service &, unsigned);
	~thread_runner ();
	void join ();
	std::vector<std::thread> threads;
};
void add_node_options (boost::program_options::options_description &);
bool handle_node_options (boost::program_options::variables_map &);
class inactive_node
{
public:
	inactive_node (boost::filesystem::path const & path = lightdag::working_path ());
	~inactive_node ();
	boost::filesystem::path path;
	boost::shared_ptr<boost::asio::io_service> service;
	lightdag::alarm alarm;
	lightdag::logging logging;
	lightdag::node_init init;
	lightdag::work_pool work;
	std::shared_ptr<lightdag::node> node;
};
}
