#pragma once

#include <lightdag/blockstore.hpp>
#include <lightdag/ledger.hpp>
#include <lightdag/node/common.hpp>

#include <atomic>
#include <future>
#include <queue>
#include <stack>
#include <unordered_set>

#include <boost/log/sources/logger.hpp>

namespace lightdag
{
class bootstrap_attempt;
class node;
enum class sync_result
{
	success,
	error,
	fork
};

/**
 * The length of every message header, parsed by lightdag::message::read_header ()
 * The 2 here represents the size of a std::bitset<16>, which is 2 chars long normally
 */
static const int bootstrap_message_header_size = sizeof (lightdag::message::magic_number) + sizeof (uint8_t) + sizeof (uint8_t) + sizeof (uint8_t) + sizeof (lightdag::message_type) + 2;

class block_synchronization
{
public:
	block_synchronization (boost::log::sources::logger_mt &);
	virtual ~block_synchronization () = default;
	// Return true if target already has block
	virtual bool synchronized (MDB_txn *, lightdag::block_hash const &) = 0;
	virtual std::unique_ptr<lightdag::block> retrieve (MDB_txn *, lightdag::block_hash const &) = 0;
	virtual lightdag::sync_result target (MDB_txn *, lightdag::block const &) = 0;
	// return true if all dependencies are synchronized
	bool add_dependency (MDB_txn *, lightdag::block const &);
	void fill_dependencies (MDB_txn *);
	lightdag::sync_result synchronize_one (MDB_txn *);
	lightdag::sync_result synchronize (MDB_txn *, lightdag::block_hash const &);
	boost::log::sources::logger_mt & log;
	std::deque<lightdag::block_hash> blocks;
};
class push_synchronization : public lightdag::block_synchronization
{
public:
	push_synchronization (lightdag::node &, std::function<lightdag::sync_result (MDB_txn *, lightdag::block const &)> const &);
	virtual ~push_synchronization () = default;
	bool synchronized (MDB_txn *, lightdag::block_hash const &) override;
	std::unique_ptr<lightdag::block> retrieve (MDB_txn *, lightdag::block_hash const &) override;
	lightdag::sync_result target (MDB_txn *, lightdag::block const &) override;
	std::function<lightdag::sync_result (MDB_txn *, lightdag::block const &)> target_m;
	lightdag::node & node;
};
class bootstrap_client;
class pull_info
{
public:
	pull_info ();
	pull_info (lightdag::account const &, lightdag::block_hash const &, lightdag::block_hash const &);
	lightdag::account account;
	lightdag::block_hash head;
	lightdag::block_hash end;
	unsigned attempts;
};
class frontier_req_client;
class bulk_push_client;
class bootstrap_attempt : public std::enable_shared_from_this<bootstrap_attempt>
{
public:
	bootstrap_attempt (std::shared_ptr<lightdag::node> node_a);
	~bootstrap_attempt ();
	void run ();
	std::shared_ptr<lightdag::bootstrap_client> connection (std::unique_lock<std::mutex> &);
	bool consume_future (std::future<bool> &);
	void populate_connections ();
	bool request_frontier (std::unique_lock<std::mutex> &);
	void request_pull (std::unique_lock<std::mutex> &);
	bool request_push (std::unique_lock<std::mutex> &);
	void add_connection (lightdag::endpoint const &);
	void pool_connection (std::shared_ptr<lightdag::bootstrap_client>);
	void stop ();
	void requeue_pull (lightdag::pull_info const &);
	void add_pull (lightdag::pull_info const &);
	bool still_pulling ();
	void process_fork (MDB_txn *, std::shared_ptr<lightdag::block>);
	void try_resolve_fork (MDB_txn *, std::shared_ptr<lightdag::block>, bool);
	void resolve_forks ();
	unsigned target_connections (size_t pulls_remaining);
	std::deque<std::weak_ptr<lightdag::bootstrap_client>> clients;
	std::weak_ptr<lightdag::bootstrap_client> connection_frontier_request;
	std::weak_ptr<lightdag::frontier_req_client> frontiers;
	std::weak_ptr<lightdag::bulk_push_client> push;
	std::deque<lightdag::pull_info> pulls;
	std::deque<std::shared_ptr<lightdag::bootstrap_client>> idle;
	std::atomic<unsigned> connections;
	std::atomic<unsigned> pulling;
	std::shared_ptr<lightdag::node> node;
	std::atomic<unsigned> account_count;
	std::atomic<uint64_t> total_blocks;
	std::unordered_map<lightdag::block_hash, std::shared_ptr<lightdag::block>> unresolved_forks;
	bool stopped;
	std::mutex mutex;
	std::condition_variable condition;
};
class frontier_req_client : public std::enable_shared_from_this<lightdag::frontier_req_client>
{
public:
	frontier_req_client (std::shared_ptr<lightdag::bootstrap_client>);
	~frontier_req_client ();
	void run ();
	void receive_frontier ();
	void received_frontier (boost::system::error_code const &, size_t);
	void request_account (lightdag::account const &, lightdag::block_hash const &);
	void unsynced (MDB_txn *, lightdag::account const &, lightdag::block_hash const &);
	void next (MDB_txn *);
	void insert_pull (lightdag::pull_info const &);
	std::shared_ptr<lightdag::bootstrap_client> connection;
	lightdag::account current;
	lightdag::account_info info;
	unsigned count;
	lightdag::account landing;
	lightdag::account faucet;
	std::chrono::steady_clock::time_point start_time;
	std::chrono::steady_clock::time_point next_report;
	std::promise<bool> promise;
};
class bulk_pull_client : public std::enable_shared_from_this<lightdag::bulk_pull_client>
{
public:
	bulk_pull_client (std::shared_ptr<lightdag::bootstrap_client>, lightdag::pull_info const &, size_t);
	~bulk_pull_client ();
	void request ();
	void receive_block ();
	void received_type ();
	void received_block (boost::system::error_code const &, size_t);
	lightdag::block_hash first ();
	std::shared_ptr<lightdag::bootstrap_client> connection;
	lightdag::block_hash expected;
	lightdag::pull_info pull;
	size_t size;
};
class bootstrap_client : public std::enable_shared_from_this<bootstrap_client>
{
public:
	bootstrap_client (std::shared_ptr<lightdag::node>, std::shared_ptr<lightdag::bootstrap_attempt>, lightdag::tcp_endpoint const &);
	~bootstrap_client ();
	void run ();
	std::shared_ptr<lightdag::bootstrap_client> shared ();
	void start_timeout ();
	void stop_timeout ();
	void stop (bool force);
	double block_rate () const;
	double elapsed_seconds () const;
	std::shared_ptr<lightdag::node> node;
	std::shared_ptr<lightdag::bootstrap_attempt> attempt;
	boost::asio::ip::tcp::socket socket;
	std::array<uint8_t, 200> receive_buffer;
	lightdag::tcp_endpoint endpoint;
	boost::asio::deadline_timer timeout;
	std::chrono::steady_clock::time_point start_time;
	std::atomic<uint64_t> block_count;
	std::atomic<bool> pending_stop;
	std::atomic<bool> hard_stop;
};
class bulk_push_client : public std::enable_shared_from_this<lightdag::bulk_push_client>
{
public:
	bulk_push_client (std::shared_ptr<lightdag::bootstrap_client> const &);
	~bulk_push_client ();
	void start ();
	void push (MDB_txn *);
	void push_block (lightdag::block const &);
	void send_finished ();
	std::shared_ptr<lightdag::bootstrap_client> connection;
	lightdag::push_synchronization synchronization;
	std::promise<bool> promise;
};
class bootstrap_initiator
{
public:
	bootstrap_initiator (lightdag::node &);
	~bootstrap_initiator ();
	void bootstrap (lightdag::endpoint const &);
	void bootstrap ();
	void run_bootstrap ();
	void notify_listeners (bool);
	void add_observer (std::function<void(bool)> const &);
	bool in_progress ();
	void process_fork (MDB_txn *, std::shared_ptr<lightdag::block>);
	void stop ();
	lightdag::node & node;
	std::shared_ptr<lightdag::bootstrap_attempt> attempt;
	bool stopped;

private:
	std::mutex mutex;
	std::condition_variable condition;
	std::vector<std::function<void(bool)>> observers;
	std::thread thread;
};
class bootstrap_server;
class bootstrap_listener
{
public:
	bootstrap_listener (boost::asio::io_service &, uint16_t, lightdag::node &);
	void start ();
	void stop ();
	void accept_connection ();
	void accept_action (boost::system::error_code const &, std::shared_ptr<boost::asio::ip::tcp::socket>);
	std::mutex mutex;
	std::unordered_map<lightdag::bootstrap_server *, std::weak_ptr<lightdag::bootstrap_server>> connections;
	lightdag::tcp_endpoint endpoint ();
	boost::asio::ip::tcp::acceptor acceptor;
	lightdag::tcp_endpoint local;
	boost::asio::io_service & service;
	lightdag::node & node;
	bool on;
};
class message;
class bootstrap_server : public std::enable_shared_from_this<lightdag::bootstrap_server>
{
public:
	bootstrap_server (std::shared_ptr<boost::asio::ip::tcp::socket>, std::shared_ptr<lightdag::node>);
	~bootstrap_server ();
	void receive ();
	void receive_header_action (boost::system::error_code const &, size_t);
	void receive_bulk_pull_action (boost::system::error_code const &, size_t);
	void receive_bulk_pull_blocks_action (boost::system::error_code const &, size_t);
	void receive_frontier_req_action (boost::system::error_code const &, size_t);
	void receive_bulk_push_action ();
	void add_request (std::unique_ptr<lightdag::message>);
	void finish_request ();
	void run_next ();
	std::array<uint8_t, 128> receive_buffer;
	std::shared_ptr<boost::asio::ip::tcp::socket> socket;
	std::shared_ptr<lightdag::node> node;
	std::mutex mutex;
	std::queue<std::unique_ptr<lightdag::message>> requests;
};
class bulk_pull;
class bulk_pull_server : public std::enable_shared_from_this<lightdag::bulk_pull_server>
{
public:
	bulk_pull_server (std::shared_ptr<lightdag::bootstrap_server> const &, std::unique_ptr<lightdag::bulk_pull>);
	void set_current_end ();
	std::unique_ptr<lightdag::block> get_next ();
	void send_next ();
	void sent_action (boost::system::error_code const &, size_t);
	void send_finished ();
	void no_block_sent (boost::system::error_code const &, size_t);
	std::shared_ptr<lightdag::bootstrap_server> connection;
	std::unique_ptr<lightdag::bulk_pull> request;
	std::vector<uint8_t> send_buffer;
	lightdag::block_hash current;
};
class bulk_pull_blocks;
class bulk_pull_blocks_server : public std::enable_shared_from_this<lightdag::bulk_pull_blocks_server>
{
public:
	bulk_pull_blocks_server (std::shared_ptr<lightdag::bootstrap_server> const &, std::unique_ptr<lightdag::bulk_pull_blocks>);
	void set_params ();
	std::unique_ptr<lightdag::block> get_next ();
	void send_next ();
	void sent_action (boost::system::error_code const &, size_t);
	void send_finished ();
	void no_block_sent (boost::system::error_code const &, size_t);
	std::shared_ptr<lightdag::bootstrap_server> connection;
	std::unique_ptr<lightdag::bulk_pull_blocks> request;
	std::vector<uint8_t> send_buffer;
	lightdag::store_iterator stream;
	lightdag::transaction stream_transaction;
	uint32_t sent_count;
	lightdag::block_hash checksum;
};
class bulk_push_server : public std::enable_shared_from_this<lightdag::bulk_push_server>
{
public:
	bulk_push_server (std::shared_ptr<lightdag::bootstrap_server> const &);
	void receive ();
	void receive_block ();
	void received_type ();
	void received_block (boost::system::error_code const &, size_t);
	std::array<uint8_t, 256> receive_buffer;
	std::shared_ptr<lightdag::bootstrap_server> connection;
};
class frontier_req;
class frontier_req_server : public std::enable_shared_from_this<lightdag::frontier_req_server>
{
public:
	frontier_req_server (std::shared_ptr<lightdag::bootstrap_server> const &, std::unique_ptr<lightdag::frontier_req>);
	void skip_old ();
	void send_next ();
	void sent_action (boost::system::error_code const &, size_t);
	void send_finished ();
	void no_block_sent (boost::system::error_code const &, size_t);
	void next ();
	std::shared_ptr<lightdag::bootstrap_server> connection;
	lightdag::account current;
	lightdag::account_info info;
	std::unique_ptr<lightdag::frontier_req> request;
	std::vector<uint8_t> send_buffer;
	size_t count;
};
}
