from .plugins.subfinder import Subfinder
from .plugins.httpx import Httpx
from .plugins.katana import Katana

target="meta.com"

print("="*60)
print("PLUGIN TEST")
print("="*60)

sub=Subfinder().run(target)

print()

print("Subfinder")

print(sub["count"])

alive=Httpx().run(
    sub["results"]
)

print()

print("Httpx")

print(alive["count"])

crawl=Katana().run(
    alive["results"]
)

print()

print("Katana")

print(crawl["count"])

print()

print("SUCCESS")
