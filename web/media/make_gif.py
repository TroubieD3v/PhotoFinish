"""Assemble docs/demo.gif from the frames of web/media/gif-frames.ts.

    python web/media/make_gif.py [FRAMES_DIR [OUT]]

FRAMES_DIR (default: $PF_MEDIA_FRAMES, else photofinish-gif-frames in the
system temp directory, as in gif-frames.ts) holds f0000.png... and frames.json (file name and time on screen
in ms of every frame). The frames are scaled to 960 px wide, frames equal to
the previous one are merged into it, and all frames share one adaptive
palette built from a sample of them, without dithering, so that flat UI
colors stay flat and the frames compress well. The last frame stays at least
3 s; the GIF loops forever. Needs Pillow 9.1 or later.
"""

import json
import pathlib
import os
import sys
import tempfile

from PIL import Image

WIDTH = 960
MIN_LAST_MS = 3000
# A frame stays at least this long; quicker followers are dropped.
MIN_MS = 60


def main() -> None:
    default = os.environ.get("PF_MEDIA_FRAMES") or os.path.join(tempfile.gettempdir(), "photofinish-gif-frames")
    src = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else default)
    if not (src / "frames.json").is_file():
        sys.exit(f"no frames.json in {src}; run node web/media/gif-frames.ts first")
    repo = pathlib.Path(__file__).resolve().parents[2]
    out = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else repo / "docs" / "demo.gif"
    spec = json.loads((src / "frames.json").read_text(encoding="utf-8"))

    frames: list[Image.Image] = []
    durations: list[int] = []
    for i, item in enumerate(spec):
        img = Image.open(src / item["file"]).convert("RGB")
        if img.width != WIDTH:
            h = round(img.height * WIDTH / img.width)
            img = img.resize((WIDTH, h), Image.Resampling.LANCZOS)
        ms = int(item["ms"])
        if frames and img.tobytes() == frames[-1].tobytes():
            durations[-1] += ms
            continue
        last = i == len(spec) - 1
        if frames and not last and durations[-1] < MIN_MS:
            # Keep the motion at a GIF-friendly rate: while the previous
            # frame has been on screen for less than MIN_MS, this one is
            # dropped and the previous one stays longer.
            durations[-1] += ms
            continue
        frames.append(img)
        durations.append(ms)
    durations[-1] = max(durations[-1], MIN_LAST_MS)

    # One palette for all frames, from a strip of evenly spaced samples.
    step = max(1, len(frames) // 12)
    sample = frames[::step]
    strip = Image.new("RGB", (WIDTH, sum(f.height for f in sample)))
    y = 0
    for f in sample:
        strip.paste(f, (0, y))
        y += f.height
    pal = strip.quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
    indexed = [f.quantize(palette=pal, dither=Image.Dither.NONE) for f in frames]

    # GIF delays are in 10 ms steps.
    durations = [max(20, round(d / 10) * 10) for d in durations]
    indexed[0].save(
        out,
        save_all=True,
        append_images=indexed[1:],
        duration=durations,
        loop=0,
        optimize=False,
        disposal=1,
    )
    size = out.stat().st_size
    print(f"{out.name}: {len(indexed)} frames, {sum(durations) / 1000:.1f} s, {size / 1024 / 1024:.2f} MiB")


if __name__ == "__main__":
    main()
