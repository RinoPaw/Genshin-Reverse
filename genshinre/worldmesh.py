"""Read source-verified OBJ triangle meshes and raycast with explicit world transforms.

Game prefab vertices are local; no world coordinates can be inferred from a
mesh name or its prefab-root (0, 0, 0) transform.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import math

Vec3 = tuple[float, float, float]
Face = tuple[int, int, int]

IDENTITY: tuple[float, ...] = (
    1., 0., 0., 0.,
    0., 1., 0., 0.,
    0., 0., 1., 0.,
    0., 0., 0., 1.,
)


@dataclass(frozen=True)
class WorldMesh:
    vertices: tuple[Vec3, ...]
    triangles: tuple[Face, ...]

    @classmethod
    def from_obj(cls, text: str) -> "WorldMesh":
        vertices: list[Vec3] = []
        triangles: list[Face] = []
        for line_no, line in enumerate(text.splitlines(), 1):
            fields = line.strip().split()
            if not fields or fields[0] not in ("v", "f"):
                continue
            if fields[0] == "v":
                if len(fields) < 4:
                    raise ValueError(f"line {line_no}: incomplete vertex")
                vertex = tuple(float(v) for v in fields[1:4])
                if any(not math.isfinite(v) for v in vertex):
                    raise ValueError(f"line {line_no}: nonfinite vertex")
                vertices.append(vertex)
                continue
            if len(fields) < 4:
                raise ValueError(f"line {line_no}: invalid face")
            corners: list[int] = []
            for token in fields[1:]:
                number = int(token.split("/")[0])
                if number == 0:
                    raise ValueError(f"line {line_no}: zero OBJ index")
                i = number - 1 if number > 0 else len(vertices) + number
                if i < 0 or i >= len(vertices):
                    raise ValueError(f"line {line_no}: invalid OBJ index")
                corners.append(i)
            for j in range(1, len(corners) - 1):
                triangles.append((corners[0], corners[j], corners[j + 1]))
        if not vertices or not triangles:
            raise ValueError("OBJ has no triangle mesh")
        return cls(tuple(vertices), tuple(triangles))

    @classmethod
    def read(cls, path: Path) -> "WorldMesh":
        return cls.from_obj(path.read_text(encoding="utf-8-sig"))

    def bounds(self) -> tuple[Vec3, Vec3]:
        return (
            tuple(min(v[i] for v in self.vertices) for i in range(3)),
            tuple(max(v[i] for v in self.vertices) for i in range(3)),
        )

    def raycast_down(
        self, x: float, z: float, *,
        world_from_local: tuple[float, ...] = IDENTITY,
        start_y: float = math.inf, minimum_up: float = 0.5,
    ) -> float | None:
        """Highest upward-facing triangle below ray origin.

        world_from_local must come from verified original scene-instance data;
        using the default identity does NOT give a Genshin world-space height.
        """
        m = world_from_local
        if len(m) != 16 or not all(math.isfinite(v) for v in m):
            raise ValueError("invalid 4x4 matrix")
        if not math.isfinite(x) or not math.isfinite(z) or math.isnan(start_y):
            raise ValueError("invalid ray origin")
        if not 0 <= minimum_up <= 1:
            raise ValueError("invalid slope threshold")
        transformed = [
            (m[0]*vx+m[1]*vy+m[2]*vz+m[3],
             m[4]*vx+m[5]*vy+m[6]*vz+m[7],
             m[8]*vx+m[9]*vy+m[10]*vz+m[11])
            for vx, vy, vz in self.vertices
        ]
        highest: float | None = None
        for a, b, c in self.triangles:
            x1, y1, z1 = transformed[a]
            x2, y2, z2 = transformed[b]
            x3, y3, z3 = transformed[c]
            dx1, dy1, dz1 = x2-x1, y2-y1, z2-z1
            dx2, dy2, dz2 = x3-x1, y3-y1, z3-z1
            nx = dy1*dz2 - dz1*dy2
            ny = dz1*dx2 - dx1*dz2
            nz = dx1*dy2 - dy1*dx2
            length = math.sqrt(nx*nx + ny*ny + nz*nz)
            if length == 0 or ny < minimum_up * length:
                continue
            area = dx1*dz2 - dx2*dz1
            if abs(area) <= 1e-12:
                continue
            u = ((x-x1)*dz2 - dx2*(z-z1)) / area
            v = (dx1*(z-z1) - (x-x1)*dz1) / area
            if u < -1e-7 or v < -1e-7 or u+v > 1+1e-7:
                continue
            y = y1 + u*dy1 + v*dy2
            if y <= start_y and (highest is None or y > highest):
                highest = y
        return highest
