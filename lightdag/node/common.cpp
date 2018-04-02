
#include <lightdag/node/common.hpp>

#include <lightdag/lib/work.hpp>
#include <lightdag/node/wallet.hpp>

std::array<uint8_t, 2> constexpr lightdag::message::magic_number;
size_t constexpr lightdag::message::ipv4_only_position;
size_t constexpr lightdag::message::bootstrap_server_position;
std::bitset<16> constexpr lightdag::message::block_type_mask;

lightdag::message::message (lightdag::message_type type_a) :
version_max (0x07),
version_using (0x07),
version_min (0x01),
type (type_a)
{
}

lightdag::message::message (bool & error_a, lightdag::stream & stream_a)
{
	error_a = read_header (stream_a, version_max, version_using, version_min, type, extensions);
}

lightdag::block_type lightdag::message::block_type () const
{
	return static_cast<lightdag::block_type> (((extensions & block_type_mask) >> 8).to_ullong ());
}

void lightdag::message::block_type_set (lightdag::block_type type_a)
{
	extensions &= ~lightdag::message::block_type_mask;
	extensions |= std::bitset<16> (static_cast<unsigned long long> (type_a) << 8);
}

bool lightdag::message::ipv4_only ()
{
	return extensions.test (ipv4_only_position);
}

void lightdag::message::ipv4_only_set (bool value_a)
{
	extensions.set (ipv4_only_position, value_a);
}

void lightdag::message::write_header (lightdag::stream & stream_a)
{
	lightdag::write (stream_a, lightdag::message::magic_number);
	lightdag::write (stream_a, version_max);
	lightdag::write (stream_a, version_using);
	lightdag::write (stream_a, version_min);
	lightdag::write (stream_a, type);
	lightdag::write (stream_a, static_cast<uint16_t> (extensions.to_ullong ()));
}

bool lightdag::message::read_header (lightdag::stream & stream_a, uint8_t & version_max_a, uint8_t & version_using_a, uint8_t & version_min_a, lightdag::message_type & type_a, std::bitset<16> & extensions_a)
{
	uint16_t extensions_l;
	std::array<uint8_t, 2> magic_number_l;
	auto result (lightdag::read (stream_a, magic_number_l));
	result = result || magic_number_l != magic_number;
	result = result || lightdag::read (stream_a, version_max_a);
	result = result || lightdag::read (stream_a, version_using_a);
	result = result || lightdag::read (stream_a, version_min_a);
	result = result || lightdag::read (stream_a, type_a);
	result = result || lightdag::read (stream_a, extensions_l);
	if (!result)
	{
		extensions_a = extensions_l;
	}
	return result;
}

lightdag::message_parser::message_parser (lightdag::message_visitor & visitor_a, lightdag::work_pool & pool_a) :
visitor (visitor_a),
pool (pool_a),
status (parse_status::success)
{
}

void lightdag::message_parser::deserialize_buffer (uint8_t const * buffer_a, size_t size_a)
{
	status = parse_status::success;
	lightdag::bufferstream header_stream (buffer_a, size_a);
	uint8_t version_max;
	uint8_t version_using;
	uint8_t version_min;
	lightdag::message_type type;
	std::bitset<16> extensions;
	if (!lightdag::message::read_header (header_stream, version_max, version_using, version_min, type, extensions))
	{
		switch (type)
		{
			case lightdag::message_type::keepalive:
			{
				deserialize_keepalive (buffer_a, size_a);
				break;
			}
			case lightdag::message_type::publish:
			{
				deserialize_publish (buffer_a, size_a);
				break;
			}
			case lightdag::message_type::confirm_req:
			{
				deserialize_confirm_req (buffer_a, size_a);
				break;
			}
			case lightdag::message_type::confirm_ack:
			{
				deserialize_confirm_ack (buffer_a, size_a);
				break;
			}
			default:
			{
				status = parse_status::invalid_message_type;
				break;
			}
		}
	}
	else
	{
		status = parse_status::invalid_header;
	}
}

void lightdag::message_parser::deserialize_keepalive (uint8_t const * buffer_a, size_t size_a)
{
	lightdag::keepalive incoming;
	lightdag::bufferstream stream (buffer_a, size_a);
	auto error_l (incoming.deserialize (stream));
	if (!error_l && at_end (stream))
	{
		visitor.keepalive (incoming);
	}
	else
	{
		status = parse_status::invalid_keepalive_message;
	}
}

void lightdag::message_parser::deserialize_publish (uint8_t const * buffer_a, size_t size_a)
{
	lightdag::publish incoming;
	lightdag::bufferstream stream (buffer_a, size_a);
	auto error_l (incoming.deserialize (stream));
	if (!error_l && at_end (stream))
	{
		if (!lightdag::work_validate (*incoming.block))
		{
			visitor.publish (incoming);
		}
		else
		{
			status = parse_status::insufficient_work;
		}
	}
	else
	{
		status = parse_status::invalid_publish_message;
	}
}

void lightdag::message_parser::deserialize_confirm_req (uint8_t const * buffer_a, size_t size_a)
{
	lightdag::confirm_req incoming;
	lightdag::bufferstream stream (buffer_a, size_a);
	auto error_l (incoming.deserialize (stream));
	if (!error_l && at_end (stream))
	{
		if (!lightdag::work_validate (*incoming.block))
		{
			visitor.confirm_req (incoming);
		}
		else
		{
			status = parse_status::insufficient_work;
		}
	}
	else
	{
		status = parse_status::invalid_confirm_req_message;
	}
}

void lightdag::message_parser::deserialize_confirm_ack (uint8_t const * buffer_a, size_t size_a)
{
	bool error_l;
	lightdag::bufferstream stream (buffer_a, size_a);
	lightdag::confirm_ack incoming (error_l, stream);
	if (!error_l && at_end (stream))
	{
		if (!lightdag::work_validate (*incoming.vote->block))
		{
			visitor.confirm_ack (incoming);
		}
		else
		{
			status = parse_status::insufficient_work;
		}
	}
	else
	{
		status = parse_status::invalid_confirm_ack_message;
	}
}

bool lightdag::message_parser::at_end (lightdag::bufferstream & stream_a)
{
	uint8_t junk;
	auto end (lightdag::read (stream_a, junk));
	return end;
}

lightdag::keepalive::keepalive () :
message (lightdag::message_type::keepalive)
{
	lightdag::endpoint endpoint (boost::asio::ip::address_v6{}, 0);
	for (auto i (peers.begin ()), n (peers.end ()); i != n; ++i)
	{
		*i = endpoint;
	}
}

void lightdag::keepalive::visit (lightdag::message_visitor & visitor_a) const
{
	visitor_a.keepalive (*this);
}

void lightdag::keepalive::serialize (lightdag::stream & stream_a)
{
	write_header (stream_a);
	for (auto i (peers.begin ()), j (peers.end ()); i != j; ++i)
	{
		assert (i->address ().is_v6 ());
		auto bytes (i->address ().to_v6 ().to_bytes ());
		write (stream_a, bytes);
		write (stream_a, i->port ());
	}
}

bool lightdag::keepalive::deserialize (lightdag::stream & stream_a)
{
	auto error (read_header (stream_a, version_max, version_using, version_min, type, extensions));
	assert (!error);
	assert (type == lightdag::message_type::keepalive);
	for (auto i (peers.begin ()), j (peers.end ()); i != j && !error; ++i)
	{
		std::array<uint8_t, 16> address;
		uint16_t port;
		if (!read (stream_a, address) && !read (stream_a, port))
		{
			*i = lightdag::endpoint (boost::asio::ip::address_v6 (address), port);
		}
		else
		{
			error = true;
		}
	}
	return error;
}

bool lightdag::keepalive::operator== (lightdag::keepalive const & other_a) const
{
	return peers == other_a.peers;
}

lightdag::publish::publish () :
message (lightdag::message_type::publish)
{
}

lightdag::publish::publish (std::shared_ptr<lightdag::block> block_a) :
message (lightdag::message_type::publish),
block (block_a)
{
	block_type_set (block->type ());
}

bool lightdag::publish::deserialize (lightdag::stream & stream_a)
{
	auto result (read_header (stream_a, version_max, version_using, version_min, type, extensions));
	assert (!result);
	assert (type == lightdag::message_type::publish);
	if (!result)
	{
		block = lightdag::deserialize_block (stream_a, block_type ());
		result = block == nullptr;
	}
	return result;
}

void lightdag::publish::serialize (lightdag::stream & stream_a)
{
	assert (block != nullptr);
	write_header (stream_a);
	block->serialize (stream_a);
}

void lightdag::publish::visit (lightdag::message_visitor & visitor_a) const
{
	visitor_a.publish (*this);
}

bool lightdag::publish::operator== (lightdag::publish const & other_a) const
{
	return *block == *other_a.block;
}

lightdag::confirm_req::confirm_req () :
message (lightdag::message_type::confirm_req)
{
}

lightdag::confirm_req::confirm_req (std::shared_ptr<lightdag::block> block_a) :
message (lightdag::message_type::confirm_req),
block (block_a)
{
	block_type_set (block->type ());
}

bool lightdag::confirm_req::deserialize (lightdag::stream & stream_a)
{
	auto result (read_header (stream_a, version_max, version_using, version_min, type, extensions));
	assert (!result);
	assert (type == lightdag::message_type::confirm_req);
	if (!result)
	{
		block = lightdag::deserialize_block (stream_a, block_type ());
		result = block == nullptr;
	}
	return result;
}

void lightdag::confirm_req::visit (lightdag::message_visitor & visitor_a) const
{
	visitor_a.confirm_req (*this);
}

void lightdag::confirm_req::serialize (lightdag::stream & stream_a)
{
	assert (block != nullptr);
	write_header (stream_a);
	block->serialize (stream_a);
}

bool lightdag::confirm_req::operator== (lightdag::confirm_req const & other_a) const
{
	return *block == *other_a.block;
}

lightdag::confirm_ack::confirm_ack (bool & error_a, lightdag::stream & stream_a) :
message (error_a, stream_a),
vote (std::make_shared<lightdag::vote> (error_a, stream_a, block_type ()))
{
}

lightdag::confirm_ack::confirm_ack (std::shared_ptr<lightdag::vote> vote_a) :
message (lightdag::message_type::confirm_ack),
vote (vote_a)
{
	block_type_set (vote->block->type ());
}

bool lightdag::confirm_ack::deserialize (lightdag::stream & stream_a)
{
	auto result (read_header (stream_a, version_max, version_using, version_min, type, extensions));
	assert (!result);
	assert (type == lightdag::message_type::confirm_ack);
	if (!result)
	{
		result = read (stream_a, vote->account);
		if (!result)
		{
			result = read (stream_a, vote->signature);
			if (!result)
			{
				result = read (stream_a, vote->sequence);
				if (!result)
				{
					vote->block = lightdag::deserialize_block (stream_a, block_type ());
					result = vote->block == nullptr;
				}
			}
		}
	}
	return result;
}

void lightdag::confirm_ack::serialize (lightdag::stream & stream_a)
{
	assert (block_type () == lightdag::block_type::send || block_type () == lightdag::block_type::receive || block_type () == lightdag::block_type::open || block_type () == lightdag::block_type::change || block_type () == lightdag::block_type::state);
	write_header (stream_a);
	vote->serialize (stream_a, block_type ());
}

bool lightdag::confirm_ack::operator== (lightdag::confirm_ack const & other_a) const
{
	auto result (*vote == *other_a.vote);
	return result;
}

void lightdag::confirm_ack::visit (lightdag::message_visitor & visitor_a) const
{
	visitor_a.confirm_ack (*this);
}

lightdag::frontier_req::frontier_req () :
message (lightdag::message_type::frontier_req)
{
}

bool lightdag::frontier_req::deserialize (lightdag::stream & stream_a)
{
	auto result (read_header (stream_a, version_max, version_using, version_min, type, extensions));
	assert (!result);
	assert (lightdag::message_type::frontier_req == type);
	if (!result)
	{
		assert (type == lightdag::message_type::frontier_req);
		result = read (stream_a, start.bytes);
		if (!result)
		{
			result = read (stream_a, age);
			if (!result)
			{
				result = read (stream_a, count);
			}
		}
	}
	return result;
}

void lightdag::frontier_req::serialize (lightdag::stream & stream_a)
{
	write_header (stream_a);
	write (stream_a, start.bytes);
	write (stream_a, age);
	write (stream_a, count);
}

void lightdag::frontier_req::visit (lightdag::message_visitor & visitor_a) const
{
	visitor_a.frontier_req (*this);
}

bool lightdag::frontier_req::operator== (lightdag::frontier_req const & other_a) const
{
	return start == other_a.start && age == other_a.age && count == other_a.count;
}

lightdag::bulk_pull::bulk_pull () :
message (lightdag::message_type::bulk_pull)
{
}

void lightdag::bulk_pull::visit (lightdag::message_visitor & visitor_a) const
{
	visitor_a.bulk_pull (*this);
}

bool lightdag::bulk_pull::deserialize (lightdag::stream & stream_a)
{
	auto result (read_header (stream_a, version_max, version_using, version_min, type, extensions));
	assert (!result);
	assert (lightdag::message_type::bulk_pull == type);
	if (!result)
	{
		assert (type == lightdag::message_type::bulk_pull);
		result = read (stream_a, start);
		if (!result)
		{
			result = read (stream_a, end);
		}
	}
	return result;
}

void lightdag::bulk_pull::serialize (lightdag::stream & stream_a)
{
	write_header (stream_a);
	write (stream_a, start);
	write (stream_a, end);
}

lightdag::bulk_pull_blocks::bulk_pull_blocks () :
message (lightdag::message_type::bulk_pull_blocks)
{
}

void lightdag::bulk_pull_blocks::visit (lightdag::message_visitor & visitor_a) const
{
	visitor_a.bulk_pull_blocks (*this);
}

bool lightdag::bulk_pull_blocks::deserialize (lightdag::stream & stream_a)
{
	auto result (read_header (stream_a, version_max, version_using, version_min, type, extensions));
	assert (!result);
	assert (lightdag::message_type::bulk_pull_blocks == type);
	if (!result)
	{
		assert (type == lightdag::message_type::bulk_pull_blocks);
		result = read (stream_a, min_hash);
		if (!result)
		{
			result = read (stream_a, max_hash);
		}

		if (!result)
		{
			result = read (stream_a, mode);
		}

		if (!result)
		{
			result = read (stream_a, max_count);
		}
	}
	return result;
}

void lightdag::bulk_pull_blocks::serialize (lightdag::stream & stream_a)
{
	write_header (stream_a);
	write (stream_a, min_hash);
	write (stream_a, max_hash);
	write (stream_a, mode);
	write (stream_a, max_count);
}

lightdag::bulk_push::bulk_push () :
message (lightdag::message_type::bulk_push)
{
}

bool lightdag::bulk_push::deserialize (lightdag::stream & stream_a)
{
	auto result (read_header (stream_a, version_max, version_using, version_min, type, extensions));
	assert (!result);
	assert (lightdag::message_type::bulk_push == type);
	return result;
}

void lightdag::bulk_push::serialize (lightdag::stream & stream_a)
{
	write_header (stream_a);
}

void lightdag::bulk_push::visit (lightdag::message_visitor & visitor_a) const
{
	visitor_a.bulk_push (*this);
}

lightdag::message_visitor::~message_visitor ()
{
}
