#pragma once

#include <chrono>
#include <cstddef>

namespace lightdag
{
// Network variants with different genesis blocks and network parameters
enum class lightdag_networks
{
	// Low work parameters, publicly known genesis key, test IP ports
	lightdag_test_network,
	// Normal work parameters, secret beta genesis key, beta IP ports
	lightdag_beta_network,
	// Normal work parameters, secret live key, live IP ports
	lightdag_live_network
};
lightdag::lightdag_networks const lightdag_network = lightdag_networks::ACTIVE_NETWORK;
std::chrono::milliseconds const transaction_timeout = std::chrono::milliseconds (1000);
}
