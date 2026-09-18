SCRIPT_VERSION = "1.7.2"
SCRIPT_DATE = "2026-09-16"

EXIT_OK           = 0   # success
EXIT_ERROR        = 1   # fatal error
EXIT_WARNING      = 2   # completed with warnings
EXIT_VERIFY_FAIL  = 3   # --verify found remaining sensitive data

def main():
    from supportutils_scrub.cli import main as _main
    _main()


if __name__ == "__main__":
    main()
