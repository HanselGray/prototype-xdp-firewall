package rest

import (
    "github.com/shirou/gopsutil/v3/cpu"
    "github.com/shirou/gopsutil/v3/mem"
    "time"
)

func getMemMB() (uint64, error) {
    v, err := mem.VirtualMemory()
    if err != nil {
        return 0, err
    }
    return v.Used / 1024 / 1024, nil
}

func getCPUPercent() (float64, error) {
    p, err := cpu.Percent(time.Second, false)
    if err != nil || len(p) == 0 {
        return 0, err
    }
    return p[0], nil
}

