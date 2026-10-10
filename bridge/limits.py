"""Apply limits to Python after OCI initialization, without host changes."""
import resource
import runpy
import sys

ADDRESS_SPACE = 134217728


def apply():
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    effective = min(ADDRESS_SPACE, hard) if hard != resource.RLIM_INFINITY else ADDRESS_SPACE
    resource.setrlimit(resource.RLIMIT_AS, (effective, effective))


if __name__ == "__main__":
    apply()
    module = sys.argv[1]
    sys.argv = [module, *sys.argv[2:]]
    runpy.run_module(module, run_name="__main__", alter_sys=True)
