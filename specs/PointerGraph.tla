---- MODULE PointerGraph ----
EXTENDS Integers, Sequences, FiniteSets

MaxNodes == 4
MaxEdges == 6

\* Node: (va, region_class, is_root)
\* region_class: 0=Image, 1=Stack, 2=Heap, 3=Mapped, 4=Other

\* Edge: (from_node, to_node, confidence)
\* confidence in {0..10} representing 0.0..1.0

VARIABLES
    node_va,          \* Seq(Int) — VA of each node
    node_cls,         \* Seq(Int) — region class
    node_root,        \* Seq(Int) — 1 if root, 0 otherwise
    edge_from,        \* Seq(Int) — source node index
    edge_to,          \* Seq(Int) — target node index
    edge_conf         \* Seq(Int) — confidence 0..10

NodeCount == Len(node_va)
EdgeCount == Len(edge_from)

\* Helper: check if node i exists
NodeExists(i) == i \in 1..NodeCount

\* Helper: check if there is an edge from i to j
HasEdge(i, j) == \E k \in 1..EdgeCount: edge_from[k] = i /\ edge_to[k] = j

\* No self-loops on non-heap nodes
NoSelfLoopsNonHeap == \A i \in 1..NodeCount:
    \A j \in 1..EdgeCount:
        (edge_from[j] = i /\ edge_to[j] = i) => node_cls[i] = 2     \* Heap

\* All edges connect existing nodes
EdgesValid == \A i \in 1..EdgeCount:
    NodeExists(edge_from[i]) /\ NodeExists(edge_to[i])

\* Confidence in valid range
ConfidenceValid == \A i \in 1..EdgeCount: edge_conf[i] \in 0..10

\* Root nodes are self-reachable
RootsReachable == \A i \in 1..NodeCount:
    node_root[i] = 1 => NodeExists(i)

\* Counts bounded
CountsBounded == NodeCount <= MaxNodes /\ EdgeCount <= MaxEdges

PointerGraphInvariant ==
    /\ NoSelfLoopsNonHeap
    /\ EdgesValid
    /\ ConfidenceValid
    /\ RootsReachable
    /\ CountsBounded

\* ---- Operations ----

AddNode(va, cls, is_root) ==
    /\ NodeCount < MaxNodes
    /\ node_va'   = Append(node_va, va)
    /\ node_cls'  = Append(node_cls, cls)
    /\ node_root' = Append(node_root, is_root)
    /\ UNCHANGED <<edge_from, edge_to, edge_conf>>

AddEdge(from, to, conf) ==
    /\ EdgeCount < MaxEdges
    /\ NodeExists(from) /\ NodeExists(to)
    /\ conf \in 0..10
    /\ ~(from = to /\ node_cls[from] /= 2)
    /\ edge_from' = Append(edge_from, from)
    /\ edge_to'   = Append(edge_to, to)
    /\ edge_conf' = Append(edge_conf, conf)
    /\ UNCHANGED <<node_va, node_cls, node_root>>

MarkRoot(node) ==
    /\ NodeExists(node)
    /\ node_root' = [node_root EXCEPT ![node] = 1]
    /\ UNCHANGED <<node_va, node_cls, edge_from, edge_to, edge_conf>>

Init ==
    /\ node_va    = <<>>
    /\ node_cls   = <<>>
    /\ node_root  = <<>>
    /\ edge_from  = <<>>
    /\ edge_to    = <<>>
    /\ edge_conf  = <<>>

Next ==
    \/ \E va \in {0,1,2,3}: \E cls \in 0..4: \E r \in {0,1}:
         AddNode(va, cls, r)
    \/ \E f,t \in 1..MaxNodes: \E c \in 0..10:
         AddEdge(f, t, c)
    \/ \E n \in 1..MaxNodes:
         MarkRoot(n)

Spec == Init /\ [][Next]_<<node_va, node_cls, node_root, edge_from, edge_to, edge_conf>>

====
