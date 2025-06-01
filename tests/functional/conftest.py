def pytest_addoption(parser):
    """Добавляет аргумент --target-ip для PyTest."""
    parser.addoption(
        "--target-ip",
        action="store",
        default=None,
        help="IP-адрес тестируемой машины (например, 192.168.0.15)"
    )