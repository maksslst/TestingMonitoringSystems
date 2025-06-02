def pytest_addoption(parser):
    parser.addoption(
        "--target-ip",
        action="store",
        default=None,
        help="IP-адрес тестируемой машины (например, 192.168.0.15)"
    )
