#include <lightdag/lib/interface.h>
#include <lightdag/node/utility.hpp>
#include <lightdag/node/working.hpp>

#include <lmdb/libraries/liblmdb/lmdb.h>

#include <ed25519-donna/ed25519.h>

boost::filesystem::path lightdag::working_path ()
{
	auto result (lightdag::app_path ());
	switch (lightdag::lightdag_network)
	{
		case lightdag::lightdag_networks::lightdag_test_network:
			result /= "LightDAGTest";
			break;
		case lightdag::lightdag_networks::lightdag_beta_network:
			result /= "LightDAGBeta";
			break;
		case lightdag::lightdag_networks::lightdag_live_network:
			result /= "LightDAG";
			break;
	}
	return result;
}

boost::filesystem::path lightdag::unique_path ()
{
	auto result (working_path () / boost::filesystem::unique_path ());
	return result;
}

lightdag::mdb_env::mdb_env (bool & error_a, boost::filesystem::path const & path_a, int max_dbs)
{
	boost::system::error_code error;
	if (path_a.has_parent_path ())
	{
		boost::filesystem::create_directories (path_a.parent_path (), error);
		if (!error)
		{
			auto status1 (mdb_env_create (&environment));
			assert (status1 == 0);
			auto status2 (mdb_env_set_maxdbs (environment, max_dbs));
			assert (status2 == 0);
			auto status3 (mdb_env_set_mapsize (environment, 1ULL * 1024 * 1024 * 1024 * 1024)); // 1 Terabyte
			assert (status3 == 0);
			// It seems if there's ever more threads than mdb_env_set_maxreaders has read slots available, we get failures on transaction creation unless MDB_NOTLS is specified
			// This can happen if something like 256 io_threads are specified in the node config
			auto status4 (mdb_env_open (environment, path_a.string ().c_str (), MDB_NOSUBDIR | MDB_NOTLS, 00600));
			error_a = status4 != 0;
		}
		else
		{
			error_a = true;
			environment = nullptr;
		}
	}
	else
	{
		error_a = true;
		environment = nullptr;
	}
}

lightdag::mdb_env::~mdb_env ()
{
	if (environment != nullptr)
	{
		mdb_env_close (environment);
	}
}

lightdag::mdb_env::operator MDB_env * () const
{
	return environment;
}

lightdag::mdb_val::mdb_val () :
value ({ 0, nullptr })
{
}

lightdag::mdb_val::mdb_val (MDB_val const & value_a) :
value (value_a)
{
}

lightdag::mdb_val::mdb_val (size_t size_a, void * data_a) :
value ({ size_a, data_a })
{
}

lightdag::mdb_val::mdb_val (lightdag::uint128_union const & val_a) :
mdb_val (sizeof (val_a), const_cast<lightdag::uint128_union *> (&val_a))
{
}

lightdag::mdb_val::mdb_val (lightdag::uint256_union const & val_a) :
mdb_val (sizeof (val_a), const_cast<lightdag::uint256_union *> (&val_a))
{
}

void * lightdag::mdb_val::data () const
{
	return value.mv_data;
}

size_t lightdag::mdb_val::size () const
{
	return value.mv_size;
}

lightdag::uint256_union lightdag::mdb_val::uint256 () const
{
	lightdag::uint256_union result;
	assert (size () == sizeof (result));
	std::copy (reinterpret_cast<uint8_t const *> (data ()), reinterpret_cast<uint8_t const *> (data ()) + sizeof (result), result.bytes.data ());
	return result;
}

lightdag::mdb_val::operator MDB_val * () const
{
	// Allow passing a temporary to a non-c++ function which doesn't have constness
	return const_cast<MDB_val *> (&value);
};

lightdag::mdb_val::operator MDB_val const & () const
{
	return value;
}

lightdag::transaction::transaction (lightdag::mdb_env & environment_a, MDB_txn * parent_a, bool write) :
environment (environment_a)
{
	auto status (mdb_txn_begin (environment_a, parent_a, write ? 0 : MDB_RDONLY, &handle));
	assert (status == 0);
}

lightdag::transaction::~transaction ()
{
	auto status (mdb_txn_commit (handle));
	assert (status == 0);
}

lightdag::transaction::operator MDB_txn * () const
{
	return handle;
}

void lightdag::open_or_create (std::fstream & stream_a, std::string const & path_a)
{
	stream_a.open (path_a, std::ios_base::in);
	if (stream_a.fail ())
	{
		stream_a.open (path_a, std::ios_base::out);
	}
	stream_a.close ();
	stream_a.open (path_a, std::ios_base::in | std::ios_base::out);
}
