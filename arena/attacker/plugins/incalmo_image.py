"""Ship the selected C2 image between Docker stores and start it on the foothold."""
from __future__ import annotations

import os
import shlex
import signal
import subprocess
import uuid

from ...experiment_log import attacker_log as log


def start_c2_image(experiment_name: str, image_id: str, ssh: list[str]) -> None:
    # Containerd and classic stores can assign different IDs to the same image.
    # A private shipment tag preserves the selection without racing the build tag.
    tag = f"incalmo/c2c:arena-{uuid.uuid4().hex}"
    tagged = False
    stage = "tag selected image"
    try:
        subprocess.run(["docker", "tag", image_id, tag],
                       check=True, capture_output=True, text=True, timeout=60)
        tagged = True
        stage = "transfer image"
        remote_load = (
            f"docker load && docker tag {tag} incalmo/c2c:latest && "
            f"docker image rm {tag} >/dev/null"
        )
        pipeline = f"docker save {tag} | gzip -1 | {shlex.join(ssh + [remote_load])}"
        with subprocess.Popen(
            ["bash", "-o", "pipefail", "-c", pipeline], start_new_session=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        ) as process:
            try:
                output, _ = process.communicate(timeout=900)
            except subprocess.TimeoutExpired as exc:
                # Killing just the shell would leave the exporter/SSH alive.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                exc.output, _ = process.communicate()
                raise
            if process.returncode:
                raise subprocess.CalledProcessError(process.returncode, process.args, output=output)

        stage = "resolve foothold image"
        loaded = subprocess.run(
            ssh + ["docker image inspect --format '{{.Id}}' incalmo/c2c:latest"],
            check=True, capture_output=True, text=True, timeout=60,
        ).stdout.strip()
        log(experiment_name, f"C2 image loaded on foothold: {loaded} (source: {image_id})")
        stage = "start container"
        subprocess.run(
            ssh + [f"docker run --pull=never -d --name c2 --network host {shlex.quote(loaded)}"],
            check=True, capture_output=True, text=True, timeout=180,
        )
        log(experiment_name, f"C2 container started from image: {loaded}")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        message = f"C2 {stage} failed: {exc}\n{exc.stdout or ''}\n{exc.stderr or ''}".strip()
        log(experiment_name, message)
        raise RuntimeError(message) from exc
    finally:
        if tagged:
            try:
                removed = subprocess.run(
                    ["docker", "image", "rm", tag],
                    capture_output=True, text=True, timeout=60,
                )
                if removed.returncode:
                    log(experiment_name, f"C2 shipment tag cleanup failed: {removed.stderr or removed.stdout}")
            except subprocess.TimeoutExpired as exc:
                log(experiment_name, f"C2 shipment tag cleanup timed out: {exc}")
