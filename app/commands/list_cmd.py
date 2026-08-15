from pathlib import Path

ROOT=Path("engagements")

def run(_):

    ROOT.mkdir(exist_ok=True)

    print()

    print("Engagements")

    print("="*40)

    for d in sorted(ROOT.iterdir()):

        if d.is_dir():

            print("-",d.name)
