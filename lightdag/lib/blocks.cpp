#include <lightdag/lib/blocks.hpp>

#include <boost/endian/conversion.hpp>

std::string lightdag::to_string_hex (uint64_t value_a)
{
	std::stringstream stream;
	stream << std::hex << std::noshowbase << std::setw (16) << std::setfill ('0');
	stream << value_a;
	return stream.str ();
}

bool lightdag::from_string_hex (std::string const & value_a, uint64_t & target_a)
{
	auto error (value_a.empty ());
	if (!error)
	{
		error = value_a.size () > 16;
		if (!error)
		{
			std::stringstream stream (value_a);
			stream << std::hex << std::noshowbase;
			try
			{
				uint64_t number_l;
				stream >> number_l;
				target_a = number_l;
				if (!stream.eof ())
				{
					error = true;
				}
			}
			catch (std::runtime_error &)
			{
				error = true;
			}
		}
	}
	return error;
}

std::string lightdag::block::to_json ()
{
	std::string result;
	serialize_json (result);
	return result;
}

lightdag::block_hash lightdag::block::hash () const
{
	lightdag::uint256_union result;
	blake2b_state hash_l;
	auto status (blake2b_init (&hash_l, sizeof (result.bytes)));
	assert (status == 0);
	hash (hash_l);
	status = blake2b_final (&hash_l, result.bytes.data (), sizeof (result.bytes));
	assert (status == 0);
	return result;
}

void lightdag::send_block::visit (lightdag::block_visitor & visitor_a) const
{
	visitor_a.send_block (*this);
}

void lightdag::send_block::hash (blake2b_state & hash_a) const
{
	hashables.hash (hash_a);
}

uint64_t lightdag::send_block::block_work () const
{
	return work;
}

void lightdag::send_block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

lightdag::send_hashables::send_hashables (lightdag::block_hash const & previous_a, lightdag::account const & destination_a, lightdag::amount const & balance_a) :
previous (previous_a),
destination (destination_a),
balance (balance_a)
{
}

lightdag::send_hashables::send_hashables (bool & error_a, lightdag::stream & stream_a)
{
	error_a = lightdag::read (stream_a, previous.bytes);
	if (!error_a)
	{
		error_a = lightdag::read (stream_a, destination.bytes);
		if (!error_a)
		{
			error_a = lightdag::read (stream_a, balance.bytes);
		}
	}
}

lightdag::send_hashables::send_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	try
	{
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto destination_l (tree_a.get<std::string> ("destination"));
		auto balance_l (tree_a.get<std::string> ("balance"));
		error_a = previous.decode_hex (previous_l);
		if (!error_a)
		{
			error_a = destination.decode_account (destination_l);
			if (!error_a)
			{
				error_a = balance.decode_hex (balance_l);
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

void lightdag::send_hashables::hash (blake2b_state & hash_a) const
{
	auto status (blake2b_update (&hash_a, previous.bytes.data (), sizeof (previous.bytes)));
	assert (status == 0);
	status = blake2b_update (&hash_a, destination.bytes.data (), sizeof (destination.bytes));
	assert (status == 0);
	status = blake2b_update (&hash_a, balance.bytes.data (), sizeof (balance.bytes));
	assert (status == 0);
}

void lightdag::send_block::serialize (lightdag::stream & stream_a) const
{
	write (stream_a, hashables.previous.bytes);
	write (stream_a, hashables.destination.bytes);
	write (stream_a, hashables.balance.bytes);
	write (stream_a, signature.bytes);
	write (stream_a, work);
}

void lightdag::send_block::serialize_json (std::string & string_a) const
{
	boost::property_tree::ptree tree;
	tree.put ("type", "send");
	std::string previous;
	hashables.previous.encode_hex (previous);
	tree.put ("previous", previous);
	tree.put ("destination", hashables.destination.to_account ());
	std::string balance;
	hashables.balance.encode_hex (balance);
	tree.put ("balance", balance);
	std::string signature_l;
	signature.encode_hex (signature_l);
	tree.put ("work", lightdag::to_string_hex (work));
	tree.put ("signature", signature_l);
	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();
}

bool lightdag::send_block::deserialize (lightdag::stream & stream_a)
{
	auto error (false);
	error = read (stream_a, hashables.previous.bytes);
	if (!error)
	{
		error = read (stream_a, hashables.destination.bytes);
		if (!error)
		{
			error = read (stream_a, hashables.balance.bytes);
			if (!error)
			{
				error = read (stream_a, signature.bytes);
				if (!error)
				{
					error = read (stream_a, work);
				}
			}
		}
	}
	return error;
}

bool lightdag::send_block::deserialize_json (boost::property_tree::ptree const & tree_a)
{
	auto error (false);
	try
	{
		assert (tree_a.get<std::string> ("type") == "send");
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto destination_l (tree_a.get<std::string> ("destination"));
		auto balance_l (tree_a.get<std::string> ("balance"));
		auto work_l (tree_a.get<std::string> ("work"));
		auto signature_l (tree_a.get<std::string> ("signature"));
		error = hashables.previous.decode_hex (previous_l);
		if (!error)
		{
			error = hashables.destination.decode_account (destination_l);
			if (!error)
			{
				error = hashables.balance.decode_hex (balance_l);
				if (!error)
				{
					error = lightdag::from_string_hex (work_l, work);
					if (!error)
					{
						error = signature.decode_hex (signature_l);
					}
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

lightdag::send_block::send_block (lightdag::block_hash const & previous_a, lightdag::account const & destination_a, lightdag::amount const & balance_a, lightdag::raw_key const & prv_a, lightdag::public_key const & pub_a, uint64_t work_a) :
hashables (previous_a, destination_a, balance_a),
signature (lightdag::sign_message (prv_a, pub_a, hash ())),
work (work_a)
{
}

lightdag::send_block::send_block (bool & error_a, lightdag::stream & stream_a) :
hashables (error_a, stream_a)
{
	if (!error_a)
	{
		error_a = lightdag::read (stream_a, signature.bytes);
		if (!error_a)
		{
			error_a = lightdag::read (stream_a, work);
		}
	}
}

lightdag::send_block::send_block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto signature_l (tree_a.get<std::string> ("signature"));
			auto work_l (tree_a.get<std::string> ("work"));
			error_a = signature.decode_hex (signature_l);
			if (!error_a)
			{
				error_a = lightdag::from_string_hex (work_l, work);
			}
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

bool lightdag::send_block::operator== (lightdag::block const & other_a) const
{
	auto other_l (dynamic_cast<lightdag::send_block const *> (&other_a));
	auto result (other_l != nullptr);
	if (result)
	{
		result = *this == *other_l;
	}
	return result;
}

bool lightdag::send_block::valid_predecessor (lightdag::block const & block_a) const
{
	bool result;
	switch (block_a.type ())
	{
		case lightdag::block_type::send:
		case lightdag::block_type::receive:
		case lightdag::block_type::open:
		case lightdag::block_type::change:
			result = true;
			break;
		default:
			result = false;
			break;
	}
	return result;
}

lightdag::block_type lightdag::send_block::type () const
{
	return lightdag::block_type::send;
}

bool lightdag::send_block::operator== (lightdag::send_block const & other_a) const
{
	auto result (hashables.destination == other_a.hashables.destination && hashables.previous == other_a.hashables.previous && hashables.balance == other_a.hashables.balance && work == other_a.work && signature == other_a.signature);
	return result;
}

lightdag::block_hash lightdag::send_block::previous () const
{
	return hashables.previous;
}

lightdag::block_hash lightdag::send_block::source () const
{
	return 0;
}

lightdag::block_hash lightdag::send_block::root () const
{
	return hashables.previous;
}

lightdag::account lightdag::send_block::representative () const
{
	return 0;
}

lightdag::signature lightdag::send_block::block_signature () const
{
	return signature;
}

void lightdag::send_block::signature_set (lightdag::uint512_union const & signature_a)
{
	signature = signature_a;
}

lightdag::open_hashables::open_hashables (lightdag::block_hash const & source_a, lightdag::account const & representative_a, lightdag::account const & account_a) :
source (source_a),
representative (representative_a),
account (account_a)
{
}

lightdag::open_hashables::open_hashables (bool & error_a, lightdag::stream & stream_a)
{
	error_a = lightdag::read (stream_a, source.bytes);
	if (!error_a)
	{
		error_a = lightdag::read (stream_a, representative.bytes);
		if (!error_a)
		{
			error_a = lightdag::read (stream_a, account.bytes);
		}
	}
}

lightdag::open_hashables::open_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	try
	{
		auto source_l (tree_a.get<std::string> ("source"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		auto account_l (tree_a.get<std::string> ("account"));
		error_a = source.decode_hex (source_l);
		if (!error_a)
		{
			error_a = representative.decode_account (representative_l);
			if (!error_a)
			{
				error_a = account.decode_account (account_l);
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

void lightdag::open_hashables::hash (blake2b_state & hash_a) const
{
	blake2b_update (&hash_a, source.bytes.data (), sizeof (source.bytes));
	blake2b_update (&hash_a, representative.bytes.data (), sizeof (representative.bytes));
	blake2b_update (&hash_a, account.bytes.data (), sizeof (account.bytes));
}

lightdag::open_block::open_block (lightdag::block_hash const & source_a, lightdag::account const & representative_a, lightdag::account const & account_a, lightdag::raw_key const & prv_a, lightdag::public_key const & pub_a, uint64_t work_a) :
hashables (source_a, representative_a, account_a),
signature (lightdag::sign_message (prv_a, pub_a, hash ())),
work (work_a)
{
	assert (!representative_a.is_zero ());
}

lightdag::open_block::open_block (lightdag::block_hash const & source_a, lightdag::account const & representative_a, lightdag::account const & account_a, std::nullptr_t) :
hashables (source_a, representative_a, account_a),
work (0)
{
	signature.clear ();
}

lightdag::open_block::open_block (bool & error_a, lightdag::stream & stream_a) :
hashables (error_a, stream_a)
{
	if (!error_a)
	{
		error_a = lightdag::read (stream_a, signature);
		if (!error_a)
		{
			error_a = lightdag::read (stream_a, work);
		}
	}
}

lightdag::open_block::open_block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto work_l (tree_a.get<std::string> ("work"));
			auto signature_l (tree_a.get<std::string> ("signature"));
			error_a = lightdag::from_string_hex (work_l, work);
			if (!error_a)
			{
				error_a = signature.decode_hex (signature_l);
			}
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

void lightdag::open_block::hash (blake2b_state & hash_a) const
{
	hashables.hash (hash_a);
}

uint64_t lightdag::open_block::block_work () const
{
	return work;
}

void lightdag::open_block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

lightdag::block_hash lightdag::open_block::previous () const
{
	lightdag::block_hash result (0);
	return result;
}

void lightdag::open_block::serialize (lightdag::stream & stream_a) const
{
	write (stream_a, hashables.source);
	write (stream_a, hashables.representative);
	write (stream_a, hashables.account);
	write (stream_a, signature);
	write (stream_a, work);
}

void lightdag::open_block::serialize_json (std::string & string_a) const
{
	boost::property_tree::ptree tree;
	tree.put ("type", "open");
	tree.put ("source", hashables.source.to_string ());
	tree.put ("representative", representative ().to_account ());
	tree.put ("account", hashables.account.to_account ());
	std::string signature_l;
	signature.encode_hex (signature_l);
	tree.put ("work", lightdag::to_string_hex (work));
	tree.put ("signature", signature_l);
	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();
}

bool lightdag::open_block::deserialize (lightdag::stream & stream_a)
{
	auto error (read (stream_a, hashables.source));
	if (!error)
	{
		error = read (stream_a, hashables.representative);
		if (!error)
		{
			error = read (stream_a, hashables.account);
			if (!error)
			{
				error = read (stream_a, signature);
				if (!error)
				{
					error = read (stream_a, work);
				}
			}
		}
	}
	return error;
}

bool lightdag::open_block::deserialize_json (boost::property_tree::ptree const & tree_a)
{
	auto error (false);
	try
	{
		assert (tree_a.get<std::string> ("type") == "open");
		auto source_l (tree_a.get<std::string> ("source"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		auto account_l (tree_a.get<std::string> ("account"));
		auto work_l (tree_a.get<std::string> ("work"));
		auto signature_l (tree_a.get<std::string> ("signature"));
		error = hashables.source.decode_hex (source_l);
		if (!error)
		{
			error = hashables.representative.decode_hex (representative_l);
			if (!error)
			{
				error = hashables.account.decode_hex (account_l);
				if (!error)
				{
					error = lightdag::from_string_hex (work_l, work);
					if (!error)
					{
						error = signature.decode_hex (signature_l);
					}
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

void lightdag::open_block::visit (lightdag::block_visitor & visitor_a) const
{
	visitor_a.open_block (*this);
}

lightdag::block_type lightdag::open_block::type () const
{
	return lightdag::block_type::open;
}

bool lightdag::open_block::operator== (lightdag::block const & other_a) const
{
	auto other_l (dynamic_cast<lightdag::open_block const *> (&other_a));
	auto result (other_l != nullptr);
	if (result)
	{
		result = *this == *other_l;
	}
	return result;
}

bool lightdag::open_block::operator== (lightdag::open_block const & other_a) const
{
	return hashables.source == other_a.hashables.source && hashables.representative == other_a.hashables.representative && hashables.account == other_a.hashables.account && work == other_a.work && signature == other_a.signature;
}

bool lightdag::open_block::valid_predecessor (lightdag::block const & block_a) const
{
	return false;
}

lightdag::block_hash lightdag::open_block::source () const
{
	return hashables.source;
}

lightdag::block_hash lightdag::open_block::root () const
{
	return hashables.account;
}

lightdag::account lightdag::open_block::representative () const
{
	return hashables.representative;
}

lightdag::signature lightdag::open_block::block_signature () const
{
	return signature;
}

void lightdag::open_block::signature_set (lightdag::uint512_union const & signature_a)
{
	signature = signature_a;
}

lightdag::change_hashables::change_hashables (lightdag::block_hash const & previous_a, lightdag::account const & representative_a) :
previous (previous_a),
representative (representative_a)
{
}

lightdag::change_hashables::change_hashables (bool & error_a, lightdag::stream & stream_a)
{
	error_a = lightdag::read (stream_a, previous);
	if (!error_a)
	{
		error_a = lightdag::read (stream_a, representative);
	}
}

lightdag::change_hashables::change_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	try
	{
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		error_a = previous.decode_hex (previous_l);
		if (!error_a)
		{
			error_a = representative.decode_account (representative_l);
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

void lightdag::change_hashables::hash (blake2b_state & hash_a) const
{
	blake2b_update (&hash_a, previous.bytes.data (), sizeof (previous.bytes));
	blake2b_update (&hash_a, representative.bytes.data (), sizeof (representative.bytes));
}

lightdag::change_block::change_block (lightdag::block_hash const & previous_a, lightdag::account const & representative_a, lightdag::raw_key const & prv_a, lightdag::public_key const & pub_a, uint64_t work_a) :
hashables (previous_a, representative_a),
signature (lightdag::sign_message (prv_a, pub_a, hash ())),
work (work_a)
{
}

lightdag::change_block::change_block (bool & error_a, lightdag::stream & stream_a) :
hashables (error_a, stream_a)
{
	if (!error_a)
	{
		error_a = lightdag::read (stream_a, signature);
		if (!error_a)
		{
			error_a = lightdag::read (stream_a, work);
		}
	}
}

lightdag::change_block::change_block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto work_l (tree_a.get<std::string> ("work"));
			auto signature_l (tree_a.get<std::string> ("signature"));
			error_a = lightdag::from_string_hex (work_l, work);
			if (!error_a)
			{
				error_a = signature.decode_hex (signature_l);
			}
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

void lightdag::change_block::hash (blake2b_state & hash_a) const
{
	hashables.hash (hash_a);
}

uint64_t lightdag::change_block::block_work () const
{
	return work;
}

void lightdag::change_block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

lightdag::block_hash lightdag::change_block::previous () const
{
	return hashables.previous;
}

void lightdag::change_block::serialize (lightdag::stream & stream_a) const
{
	write (stream_a, hashables.previous);
	write (stream_a, hashables.representative);
	write (stream_a, signature);
	write (stream_a, work);
}

void lightdag::change_block::serialize_json (std::string & string_a) const
{
	boost::property_tree::ptree tree;
	tree.put ("type", "change");
	tree.put ("previous", hashables.previous.to_string ());
	tree.put ("representative", representative ().to_account ());
	tree.put ("work", lightdag::to_string_hex (work));
	std::string signature_l;
	signature.encode_hex (signature_l);
	tree.put ("signature", signature_l);
	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();
}

bool lightdag::change_block::deserialize (lightdag::stream & stream_a)
{
	auto error (read (stream_a, hashables.previous));
	if (!error)
	{
		error = read (stream_a, hashables.representative);
		if (!error)
		{
			error = read (stream_a, signature);
			if (!error)
			{
				error = read (stream_a, work);
			}
		}
	}
	return error;
}

bool lightdag::change_block::deserialize_json (boost::property_tree::ptree const & tree_a)
{
	auto error (false);
	try
	{
		assert (tree_a.get<std::string> ("type") == "change");
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		auto work_l (tree_a.get<std::string> ("work"));
		auto signature_l (tree_a.get<std::string> ("signature"));
		error = hashables.previous.decode_hex (previous_l);
		if (!error)
		{
			error = hashables.representative.decode_hex (representative_l);
			if (!error)
			{
				error = lightdag::from_string_hex (work_l, work);
				if (!error)
				{
					error = signature.decode_hex (signature_l);
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

void lightdag::change_block::visit (lightdag::block_visitor & visitor_a) const
{
	visitor_a.change_block (*this);
}

lightdag::block_type lightdag::change_block::type () const
{
	return lightdag::block_type::change;
}

bool lightdag::change_block::operator== (lightdag::block const & other_a) const
{
	auto other_l (dynamic_cast<lightdag::change_block const *> (&other_a));
	auto result (other_l != nullptr);
	if (result)
	{
		result = *this == *other_l;
	}
	return result;
}

bool lightdag::change_block::operator== (lightdag::change_block const & other_a) const
{
	return hashables.previous == other_a.hashables.previous && hashables.representative == other_a.hashables.representative && work == other_a.work && signature == other_a.signature;
}

bool lightdag::change_block::valid_predecessor (lightdag::block const & block_a) const
{
	bool result;
	switch (block_a.type ())
	{
		case lightdag::block_type::send:
		case lightdag::block_type::receive:
		case lightdag::block_type::open:
		case lightdag::block_type::change:
			result = true;
			break;
		default:
			result = false;
			break;
	}
	return result;
}

lightdag::block_hash lightdag::change_block::source () const
{
	return 0;
}

lightdag::block_hash lightdag::change_block::root () const
{
	return hashables.previous;
}

lightdag::account lightdag::change_block::representative () const
{
	return hashables.representative;
}

lightdag::signature lightdag::change_block::block_signature () const
{
	return signature;
}

void lightdag::change_block::signature_set (lightdag::uint512_union const & signature_a)
{
	signature = signature_a;
}

lightdag::state_hashables::state_hashables (lightdag::account const & account_a, lightdag::block_hash const & previous_a, lightdag::account const & representative_a, lightdag::amount const & balance_a, lightdag::uint256_union const & link_a) :
account (account_a),
previous (previous_a),
representative (representative_a),
balance (balance_a),
link (link_a)
{
}

lightdag::state_hashables::state_hashables (bool & error_a, lightdag::stream & stream_a)
{
	error_a = lightdag::read (stream_a, account);
	if (!error_a)
	{
		error_a = lightdag::read (stream_a, previous);
		if (!error_a)
		{
			error_a = lightdag::read (stream_a, representative);
			if (!error_a)
			{
				error_a = lightdag::read (stream_a, balance);
				if (!error_a)
				{
					error_a = lightdag::read (stream_a, link);
				}
			}
		}
	}
}

lightdag::state_hashables::state_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	try
	{
		auto account_l (tree_a.get<std::string> ("account"));
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		auto balance_l (tree_a.get<std::string> ("balance"));
		auto link_l (tree_a.get<std::string> ("link"));
		error_a = account.decode_account (account_l);
		if (!error_a)
		{
			error_a = previous.decode_hex (previous_l);
			if (!error_a)
			{
				error_a = representative.decode_account (representative_l);
				if (!error_a)
				{
					error_a = balance.decode_dec (balance_l);
					if (!error_a)
					{
						error_a = link.decode_account (link_l) && link.decode_hex (link_l);
					}
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

void lightdag::state_hashables::hash (blake2b_state & hash_a) const
{
	blake2b_update (&hash_a, account.bytes.data (), sizeof (account.bytes));
	blake2b_update (&hash_a, previous.bytes.data (), sizeof (previous.bytes));
	blake2b_update (&hash_a, representative.bytes.data (), sizeof (representative.bytes));
	blake2b_update (&hash_a, balance.bytes.data (), sizeof (balance.bytes));
	blake2b_update (&hash_a, link.bytes.data (), sizeof (link.bytes));
}

lightdag::state_block::state_block (lightdag::account const & account_a, lightdag::block_hash const & previous_a, lightdag::account const & representative_a, lightdag::amount const & balance_a, lightdag::uint256_union const & link_a, lightdag::raw_key const & prv_a, lightdag::public_key const & pub_a, uint64_t work_a) :
hashables (account_a, previous_a, representative_a, balance_a, link_a),
signature (lightdag::sign_message (prv_a, pub_a, hash ())),
work (work_a)
{
}

lightdag::state_block::state_block (bool & error_a, lightdag::stream & stream_a) :
hashables (error_a, stream_a)
{
	if (!error_a)
	{
		error_a = lightdag::read (stream_a, signature);
		if (!error_a)
		{
			error_a = lightdag::read (stream_a, work);
			boost::endian::big_to_native_inplace (work);
		}
	}
}

lightdag::state_block::state_block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto type_l (tree_a.get<std::string> ("type"));
			auto signature_l (tree_a.get<std::string> ("signature"));
			auto work_l (tree_a.get<std::string> ("work"));
			error_a = type_l != "state";
			if (!error_a)
			{
				error_a = lightdag::from_string_hex (work_l, work);
				if (!error_a)
				{
					error_a = signature.decode_hex (signature_l);
				}
			}
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

void lightdag::state_block::hash (blake2b_state & hash_a) const
{
	lightdag::uint256_union preamble (static_cast<uint64_t> (lightdag::block_type::state));
	blake2b_update (&hash_a, preamble.bytes.data (), preamble.bytes.size ());
	hashables.hash (hash_a);
}

uint64_t lightdag::state_block::block_work () const
{
	return work;
}

void lightdag::state_block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

lightdag::block_hash lightdag::state_block::previous () const
{
	return hashables.previous;
}

void lightdag::state_block::serialize (lightdag::stream & stream_a) const
{
	write (stream_a, hashables.account);
	write (stream_a, hashables.previous);
	write (stream_a, hashables.representative);
	write (stream_a, hashables.balance);
	write (stream_a, hashables.link);
	write (stream_a, signature);
	write (stream_a, boost::endian::native_to_big (work));
}

void lightdag::state_block::serialize_json (std::string & string_a) const
{
	boost::property_tree::ptree tree;
	tree.put ("type", "state");
	tree.put ("account", hashables.account.to_account ());
	tree.put ("previous", hashables.previous.to_string ());
	tree.put ("representative", representative ().to_account ());
	tree.put ("balance", hashables.balance.to_string_dec ());
	tree.put ("link", hashables.link.to_string ());
	tree.put ("link_as_account", hashables.link.to_account ());
	std::string signature_l;
	signature.encode_hex (signature_l);
	tree.put ("signature", signature_l);
	tree.put ("work", lightdag::to_string_hex (work));
	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();
}

bool lightdag::state_block::deserialize (lightdag::stream & stream_a)
{
	auto error (read (stream_a, hashables.account));
	if (!error)
	{
		error = read (stream_a, hashables.previous);
		if (!error)
		{
			error = read (stream_a, hashables.representative);
			if (!error)
			{
				error = read (stream_a, hashables.balance);
				if (!error)
				{
					error = read (stream_a, hashables.link);
					if (!error)
					{
						error = read (stream_a, signature);
						if (!error)
						{
							error = read (stream_a, work);
							boost::endian::big_to_native_inplace (work);
						}
					}
				}
			}
		}
	}
	return error;
}

bool lightdag::state_block::deserialize_json (boost::property_tree::ptree const & tree_a)
{
	auto error (false);
	try
	{
		assert (tree_a.get<std::string> ("type") == "state");
		auto account_l (tree_a.get<std::string> ("account"));
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		auto balance_l (tree_a.get<std::string> ("balance"));
		auto link_l (tree_a.get<std::string> ("link"));
		auto work_l (tree_a.get<std::string> ("work"));
		auto signature_l (tree_a.get<std::string> ("signature"));
		error = hashables.account.decode_account (account_l);
		if (!error)
		{
			error = hashables.previous.decode_hex (previous_l);
			if (!error)
			{
				error = hashables.representative.decode_account (representative_l);
				if (!error)
				{
					error = hashables.balance.decode_dec (balance_l);
					if (!error)
					{
						error = hashables.link.decode_account (link_l) && hashables.link.decode_hex (link_l);
						if (!error)
						{
							error = lightdag::from_string_hex (work_l, work);
							if (!error)
							{
								error = signature.decode_hex (signature_l);
							}
						}
					}
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

void lightdag::state_block::visit (lightdag::block_visitor & visitor_a) const
{
	visitor_a.state_block (*this);
}

lightdag::block_type lightdag::state_block::type () const
{
	return lightdag::block_type::state;
}

bool lightdag::state_block::operator== (lightdag::block const & other_a) const
{
	auto other_l (dynamic_cast<lightdag::state_block const *> (&other_a));
	auto result (other_l != nullptr);
	if (result)
	{
		result = *this == *other_l;
	}
	return result;
}

bool lightdag::state_block::operator== (lightdag::state_block const & other_a) const
{
	return hashables.account == other_a.hashables.account && hashables.previous == other_a.hashables.previous && hashables.representative == other_a.hashables.representative && hashables.balance == other_a.hashables.balance && hashables.link == other_a.hashables.link && signature == other_a.signature && work == other_a.work;
}

bool lightdag::state_block::valid_predecessor (lightdag::block const & block_a) const
{
	return true;
}

lightdag::block_hash lightdag::state_block::source () const
{
	return 0;
}

lightdag::block_hash lightdag::state_block::root () const
{
	return !hashables.previous.is_zero () ? hashables.previous : hashables.account;
}

lightdag::account lightdag::state_block::representative () const
{
	return hashables.representative;
}

lightdag::signature lightdag::state_block::block_signature () const
{
	return signature;
}

void lightdag::state_block::signature_set (lightdag::uint512_union const & signature_a)
{
	signature = signature_a;
}

std::unique_ptr<lightdag::block> lightdag::deserialize_block_json (boost::property_tree::ptree const & tree_a)
{
	std::unique_ptr<lightdag::block> result;
	try
	{
		auto type (tree_a.get<std::string> ("type"));
		if (type == "receive")
		{
			bool error;
			std::unique_ptr<lightdag::receive_block> obj (new lightdag::receive_block (error, tree_a));
			if (!error)
			{
				result = std::move (obj);
			}
		}
		else if (type == "send")
		{
			bool error;
			std::unique_ptr<lightdag::send_block> obj (new lightdag::send_block (error, tree_a));
			if (!error)
			{
				result = std::move (obj);
			}
		}
		else if (type == "open")
		{
			bool error;
			std::unique_ptr<lightdag::open_block> obj (new lightdag::open_block (error, tree_a));
			if (!error)
			{
				result = std::move (obj);
			}
		}
		else if (type == "change")
		{
			bool error;
			std::unique_ptr<lightdag::change_block> obj (new lightdag::change_block (error, tree_a));
			if (!error)
			{
				result = std::move (obj);
			}
		}
		else if (type == "state")
		{
			bool error;
			std::unique_ptr<lightdag::state_block> obj (new lightdag::state_block (error, tree_a));
			if (!error)
			{
				result = std::move (obj);
			}
		}
	}
	catch (std::runtime_error const &)
	{
	}
	return result;
}

std::unique_ptr<lightdag::block> lightdag::deserialize_block (lightdag::stream & stream_a)
{
	lightdag::block_type type;
	auto error (read (stream_a, type));
	std::unique_ptr<lightdag::block> result;
	if (!error)
	{
		result = lightdag::deserialize_block (stream_a, type);
	}
	return result;
}

std::unique_ptr<lightdag::block> lightdag::deserialize_block (lightdag::stream & stream_a, lightdag::block_type type_a)
{
	std::unique_ptr<lightdag::block> result;
	switch (type_a)
	{
		case lightdag::block_type::receive:
		{
			bool error;
			std::unique_ptr<lightdag::receive_block> obj (new lightdag::receive_block (error, stream_a));
			if (!error)
			{
				result = std::move (obj);
			}
			break;
		}
		case lightdag::block_type::send:
		{
			bool error;
			std::unique_ptr<lightdag::send_block> obj (new lightdag::send_block (error, stream_a));
			if (!error)
			{
				result = std::move (obj);
			}
			break;
		}
		case lightdag::block_type::open:
		{
			bool error;
			std::unique_ptr<lightdag::open_block> obj (new lightdag::open_block (error, stream_a));
			if (!error)
			{
				result = std::move (obj);
			}
			break;
		}
		case lightdag::block_type::change:
		{
			bool error;
			std::unique_ptr<lightdag::change_block> obj (new lightdag::change_block (error, stream_a));
			if (!error)
			{
				result = std::move (obj);
			}
			break;
		}
		case lightdag::block_type::state:
		{
			bool error;
			std::unique_ptr<lightdag::state_block> obj (new lightdag::state_block (error, stream_a));
			if (!error)
			{
				result = std::move (obj);
			}
			break;
		}
		default:
			assert (false);
			break;
	}
	return result;
}

void lightdag::receive_block::visit (lightdag::block_visitor & visitor_a) const
{
	visitor_a.receive_block (*this);
}

bool lightdag::receive_block::operator== (lightdag::receive_block const & other_a) const
{
	auto result (hashables.previous == other_a.hashables.previous && hashables.source == other_a.hashables.source && work == other_a.work && signature == other_a.signature);
	return result;
}

bool lightdag::receive_block::deserialize (lightdag::stream & stream_a)
{
	auto error (false);
	error = read (stream_a, hashables.previous.bytes);
	if (!error)
	{
		error = read (stream_a, hashables.source.bytes);
		if (!error)
		{
			error = read (stream_a, signature.bytes);
			if (!error)
			{
				error = read (stream_a, work);
			}
		}
	}
	return error;
}

bool lightdag::receive_block::deserialize_json (boost::property_tree::ptree const & tree_a)
{
	auto error (false);
	try
	{
		assert (tree_a.get<std::string> ("type") == "receive");
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto source_l (tree_a.get<std::string> ("source"));
		auto work_l (tree_a.get<std::string> ("work"));
		auto signature_l (tree_a.get<std::string> ("signature"));
		error = hashables.previous.decode_hex (previous_l);
		if (!error)
		{
			error = hashables.source.decode_hex (source_l);
			if (!error)
			{
				error = lightdag::from_string_hex (work_l, work);
				if (!error)
				{
					error = signature.decode_hex (signature_l);
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

void lightdag::receive_block::serialize (lightdag::stream & stream_a) const
{
	write (stream_a, hashables.previous.bytes);
	write (stream_a, hashables.source.bytes);
	write (stream_a, signature.bytes);
	write (stream_a, work);
}

void lightdag::receive_block::serialize_json (std::string & string_a) const
{
	boost::property_tree::ptree tree;
	tree.put ("type", "receive");
	std::string previous;
	hashables.previous.encode_hex (previous);
	tree.put ("previous", previous);
	std::string source;
	hashables.source.encode_hex (source);
	tree.put ("source", source);
	std::string signature_l;
	signature.encode_hex (signature_l);
	tree.put ("work", lightdag::to_string_hex (work));
	tree.put ("signature", signature_l);
	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();
}

lightdag::receive_block::receive_block (lightdag::block_hash const & previous_a, lightdag::block_hash const & source_a, lightdag::raw_key const & prv_a, lightdag::public_key const & pub_a, uint64_t work_a) :
hashables (previous_a, source_a),
signature (lightdag::sign_message (prv_a, pub_a, hash ())),
work (work_a)
{
}

lightdag::receive_block::receive_block (bool & error_a, lightdag::stream & stream_a) :
hashables (error_a, stream_a)
{
	if (!error_a)
	{
		error_a = lightdag::read (stream_a, signature);
		if (!error_a)
		{
			error_a = lightdag::read (stream_a, work);
		}
	}
}

lightdag::receive_block::receive_block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto signature_l (tree_a.get<std::string> ("signature"));
			auto work_l (tree_a.get<std::string> ("work"));
			error_a = signature.decode_hex (signature_l);
			if (!error_a)
			{
				error_a = lightdag::from_string_hex (work_l, work);
			}
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

void lightdag::receive_block::hash (blake2b_state & hash_a) const
{
	hashables.hash (hash_a);
}

uint64_t lightdag::receive_block::block_work () const
{
	return work;
}

void lightdag::receive_block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

bool lightdag::receive_block::operator== (lightdag::block const & other_a) const
{
	auto other_l (dynamic_cast<lightdag::receive_block const *> (&other_a));
	auto result (other_l != nullptr);
	if (result)
	{
		result = *this == *other_l;
	}
	return result;
}

bool lightdag::receive_block::valid_predecessor (lightdag::block const & block_a) const
{
	bool result;
	switch (block_a.type ())
	{
		case lightdag::block_type::send:
		case lightdag::block_type::receive:
		case lightdag::block_type::open:
		case lightdag::block_type::change:
			result = true;
			break;
		default:
			result = false;
			break;
	}
	return result;
}

lightdag::block_hash lightdag::receive_block::previous () const
{
	return hashables.previous;
}

lightdag::block_hash lightdag::receive_block::source () const
{
	return hashables.source;
}

lightdag::block_hash lightdag::receive_block::root () const
{
	return hashables.previous;
}

lightdag::account lightdag::receive_block::representative () const
{
	return 0;
}

lightdag::signature lightdag::receive_block::block_signature () const
{
	return signature;
}

void lightdag::receive_block::signature_set (lightdag::uint512_union const & signature_a)
{
	signature = signature_a;
}

lightdag::block_type lightdag::receive_block::type () const
{
	return lightdag::block_type::receive;
}

lightdag::receive_hashables::receive_hashables (lightdag::block_hash const & previous_a, lightdag::block_hash const & source_a) :
previous (previous_a),
source (source_a)
{
}

lightdag::receive_hashables::receive_hashables (bool & error_a, lightdag::stream & stream_a)
{
	error_a = lightdag::read (stream_a, previous.bytes);
	if (!error_a)
	{
		error_a = lightdag::read (stream_a, source.bytes);
	}
}

lightdag::receive_hashables::receive_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	try
	{
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto source_l (tree_a.get<std::string> ("source"));
		error_a = previous.decode_hex (previous_l);
		if (!error_a)
		{
			error_a = source.decode_hex (source_l);
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

void lightdag::receive_hashables::hash (blake2b_state & hash_a) const
{
	blake2b_update (&hash_a, previous.bytes.data (), sizeof (previous.bytes));
	blake2b_update (&hash_a, source.bytes.data (), sizeof (source.bytes));
}
