package contentdiscovery

import "sort"

const (
	classCandidate = "candidate"
	classNoise     = "noise"
	classRedirect  = "redirect"
	classFiltered  = "filtered"
)

const clusterNoiseFraction = 0.55

const minClusterSamples = 3

func classify(hits []Hit, baseline Baseline, filterSizes map[int64]bool) []Hit {
	baselineHashes := map[string]bool{}
	for _, h := range baseline.BodyHashes {
		baselineHashes[h] = true
	}
	statusCounts := map[int]map[int64]int{}
	total := 0
	for _, h := range hits {
		if h.Status >= 300 && h.Status < 400 {
			continue
		}
		if statusCounts[h.Status] == nil {
			statusCounts[h.Status] = map[int64]int{}
		}
		statusCounts[h.Status][h.Length]++
		total++
	}
	dominant := dominantClusters(statusCounts, total)
	out := make([]Hit, 0, len(hits))
	for _, h := range hits {
		h.Class = decide(h, baseline, baselineHashes, dominant, filterSizes)
		out = append(out, h)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Class != out[j].Class {
			return classRank(out[i].Class) < classRank(out[j].Class)
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func decide(h Hit, baseline Baseline, baselineHashes map[string]bool, dominant map[int]int64, filterSizes map[int64]bool) string {
	if filterSizes[h.Length] {
		return classFiltered
	}
	if h.Status >= 300 && h.Status < 400 {
		return classRedirect
	}
	if baseline.CatchAll && h.Status == baseline.Status {
		if baselineHashes[h.BodyHash] {
			return classNoise
		}
		if baseline.StableLength && h.Length == baseline.Length {
			return classNoise
		}
		if baseline.StableShape && h.Words == baseline.Words && h.Lines == baseline.Lines {
			return classNoise
		}
	}
	if size, ok := dominant[h.Status]; ok && h.Length == size {
		return classNoise
	}
	return classCandidate
}

func dominantClusters(statusCounts map[int]map[int64]int, total int) map[int]int64 {
	dominant := map[int]int64{}
	if total == 0 {
		return dominant
	}
	for status, sizes := range statusCounts {
		var bestSize int64
		best := 0
		for size, count := range sizes {
			if count > best {
				best = count
				bestSize = size
			}
		}
		if best >= minClusterSamples && float64(best)/float64(total) >= clusterNoiseFraction {
			dominant[status] = bestSize
		}
	}
	return dominant
}

func classRank(class string) int {
	switch class {
	case classCandidate:
		return 0
	case classRedirect:
		return 1
	case classNoise:
		return 2
	case classFiltered:
		return 3
	}
	return 4
}
