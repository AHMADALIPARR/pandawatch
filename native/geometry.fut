-- Futhark: graph reachability and monotone risk propagation over dense arrays.
-- A[i,j] indicates a modeled directed edge i -> j.

def reachable [n] (adj: [n][n]bool) (seed: [n]bool) : [n]bool =
  loop seen = seed for _i < n do
    map (\j -> seen[j] ||
      reduce (||) false
        (map2 (\s row -> s && row[j]) seen adj)) (iota n)

def protected_reachable [n]
  (adj: [n][n]bool) (source: [n]bool) (protected: [n]bool)
  : [n]bool =
  map2 (&&) (reachable adj source) protected

-- Nonnegative i32 scores, largest reachable source score per component.
-- Scores never decrease. This is a prioritization heuristic, not exploitability.
def recursive_risk [n]
  (adj: [n][n]bool) (initial: [n]i32) : [n]i32 =
  loop scores = initial for _i < n do
    map (\j ->
      reduce (\x y -> if x > y then x else y) scores[j]
        (map2 (\score row -> if row[j] then score else 0)
          scores adj)) (iota n)

entry main [n] (adj: [n][n]bool) (seed: [n]bool)
  : [n]bool = reachable adj seed
