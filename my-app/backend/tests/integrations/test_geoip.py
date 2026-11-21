import sys
import types

from app.integrations.geoip import GeoIpClient

# Record shapes of the MaxMind database formats: GeoLite2-City and GeoLite2-ASN.
CITY_RECORD = {
    "city": {"geoname_id": 2306104, "names": {"en": "Accra", "fr": "Accra"}},
    "continent": {"code": "AF", "geoname_id": 6255146, "names": {"en": "Africa"}},
    "country": {"geoname_id": 2300660, "iso_code": "GH", "names": {"en": "Ghana", "de": "Ghana"}},
    "location": {"accuracy_radius": 50, "latitude": 5.556, "longitude": -0.1969, "time_zone": "Africa/Accra"},
    "registered_country": {"geoname_id": 2300660, "iso_code": "GH", "names": {"en": "Ghana"}},
}
COUNTRY_RECORD = {"country": {"iso_code": "GH", "names": {"en": "Ghana"}}}
ASN_RECORD = {"autonomous_system_number": 15169, "autonomous_system_organization": "GOOGLE"}


class FakeReader:
    """Stands in for maxminddb.Reader: get(), metadata(), close()."""

    def __init__(self, records: dict, database_type: str = "GeoLite2-City"):
        self.records = records
        self.database_type = database_type
        self.lookups: list[str] = []
        self.closed = False

    def get(self, ip: str):
        self.lookups.append(ip)
        if "not-an-ip" in ip:
            raise ValueError(f"'{ip}' does not appear to be an IPv4 or IPv6 address")
        return self.records.get(ip)

    def metadata(self):
        return types.SimpleNamespace(database_type=self.database_type)

    def close(self):
        self.closed = True


def make_client(records: dict, **kwargs):
    client = GeoIpClient({}, {"database_path": "/data/GeoLite2-City.mmdb"})
    reader = FakeReader(records, **kwargs)
    client._reader = reader
    return client, reader


def fake_maxminddb(monkeypatch, reader=None, error=None):
    opened: list[str] = []

    def open_database(path):
        opened.append(path)
        if error:
            raise error
        return reader

    monkeypatch.setitem(sys.modules, "maxminddb", types.SimpleNamespace(open_database=open_database))
    return opened


def test_declares_contract():
    assert GeoIpClient.platform_name == "geoip"
    assert GeoIpClient.category == "enrichment"
    assert GeoIpClient.enriches == ("ip",)
    assert GeoIpClient.required_credentials == []
    assert GeoIpClient.optional_config == ["database_path"]
    assert GeoIpClient.auth_type == "api_key"


async def test_city_record_mapping():
    client, reader = make_client({"154.160.1.1": CITY_RECORD})
    result = await client.enrich("ip", " 154.160.1.1 ")
    assert reader.lookups == ["154.160.1.1"]
    assert result == {
        "verdict": "unknown",
        "summary": "154.160.1.1 is located in Accra, Ghana.",
        "country": "Ghana",
        "country_code": "GH",
        "city": "Accra",
    }


async def test_country_only_record_has_no_city_key():
    client, _ = make_client({"154.160.1.1": COUNTRY_RECORD})
    result = await client.enrich("ip", "154.160.1.1")
    assert result["country"] == "Ghana" and "city" not in result and "asn" not in result
    assert result["verdict"] == "unknown"


async def test_asn_record_mapping():
    client, _ = make_client({"8.8.8.8": ASN_RECORD}, database_type="GeoLite2-ASN")
    result = await client.enrich("ip", "8.8.8.8")
    assert result["asn"] == 15169 and result["organisation"] == "GOOGLE"
    assert result["country"] is None
    assert result["summary"] == "8.8.8.8 is on the network of AS15169 GOOGLE."
    assert result["verdict"] == "unknown"


async def test_not_in_database_is_none():
    client, _ = make_client({})
    assert await client.enrich("ip", "10.0.0.1") is None


async def test_invalid_ip_is_none():
    client, _ = make_client({})
    assert await client.enrich("ip", "not-an-ip") is None


async def test_other_kinds_do_not_touch_the_database():
    client, reader = make_client({"example.com": CITY_RECORD})
    assert await client.enrich("domain", "example.com") is None
    assert reader.lookups == []


async def test_opens_the_configured_file_once_with_maxminddb(monkeypatch, tmp_path):
    database = tmp_path / "GeoLite2-City.mmdb"
    database.write_bytes(b"not a real database")
    reader = FakeReader({"154.160.1.1": CITY_RECORD})
    opened = fake_maxminddb(monkeypatch, reader)

    client = GeoIpClient({}, {"database_path": str(database)})
    assert (await client.enrich("ip", "154.160.1.1"))["city"] == "Accra"
    assert (await client.enrich("ip", "154.160.1.1"))["city"] == "Accra"
    assert opened == [str(database)]

    result = await client.test_connection()
    assert result == {"success": True, "message": "GeoIP database loaded (GeoLite2-City)"}
    assert (await client.get_health())["status"] == "healthy"

    await client.close()
    assert reader.closed is True


async def test_missing_package_fails_clearly(monkeypatch, tmp_path):
    database = tmp_path / "db.mmdb"
    database.write_bytes(b"x")
    monkeypatch.setitem(sys.modules, "maxminddb", None)   # makes `import maxminddb` raise ImportError
    client = GeoIpClient({}, {"database_path": str(database)})
    result = await client.test_connection()
    assert result["success"] is False and "maxminddb" in result["message"] and "not installed" in result["message"]
    assert await client.enrich("ip", "8.8.8.8") is None
    assert (await client.get_health())["status"] == "error"


async def test_missing_file_fails_clearly(monkeypatch, tmp_path):
    opened = fake_maxminddb(monkeypatch, FakeReader({}))
    missing = str(tmp_path / "nope.mmdb")
    client = GeoIpClient({}, {"database_path": missing})
    result = await client.test_connection()
    assert result["success"] is False and "not found" in result["message"] and missing in result["message"]
    assert await client.enrich("ip", "8.8.8.8") is None
    assert opened == []


async def test_no_path_configured_fails_clearly():
    client = GeoIpClient({})
    result = await client.test_connection()
    assert result["success"] is False and "database_path" in result["message"]
    assert await client.enrich("ip", "8.8.8.8") is None


async def test_corrupt_database_fails_clearly(monkeypatch, tmp_path):
    database = tmp_path / "bad.mmdb"
    database.write_bytes(b"x")
    fake_maxminddb(monkeypatch, error=RuntimeError("invalid database metadata"))
    client = GeoIpClient({}, {"database_path": str(database)})
    result = await client.test_connection()
    assert result["success"] is False and "Could not open" in result["message"]
    assert await client.enrich("ip", "8.8.8.8") is None
