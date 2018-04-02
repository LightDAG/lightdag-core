#include <lightdag/lib/utility.hpp>

#include <windows.h>

void lightdag::work_thread_reprioritize ()
{
	auto SUCCESS (SetThreadPriority (GetCurrentThread (), THREAD_MODE_BACKGROUND_BEGIN));
}
