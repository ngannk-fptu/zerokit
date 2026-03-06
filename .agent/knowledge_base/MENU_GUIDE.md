# 🎯 Interactive Hunt Menu - Quick Start

## Usage

```bash
# Start interactive menu
python hunt_menu.py vul/admin-bar

# Or let it prompt you for target
python hunt_menu.py
```

## Menu Options

| Key | Action | Description |
|-----|--------|-------------|
| **1-8** | Run specific phase | Execute individual phase |
| **9** | Full pipeline | Run all phases automatically |
| **R** | Resume | Continue from last checkpoint |
| **S** | Show summary | Display current context info |
| **C** | Clear | Reset all progress |
| **Q** | Quit | Exit menu |

## The 9 Phases

1. 🗺️ **Profiling & Attack Surface** - Map entry points
2. 🧠 **Threat Modeling** - Generate hypotheses  
3. 🔍 **Static Detection** - Semgrep + CodeQL + Joern
4. ✅ **Verification** - Run PoC exploits
5. 🔄 **Variant Analysis** - Find related bugs
6. 🎯 **Root Cause Analysis** - Analyze causes
7. 🔧 **Autonomous Patching** - Auto-fix bugs
8. 📄 **Reporting** - Generate report

## Example Session

```bash
$ python hunt_menu.py vul/admin-bar

Choose an option: 1   # Run Profiling
✓ Phase 1 completed! Found 23 entry points

Choose an option: 2   # Run Threat Modeling  
✓ Phase 2 completed! Generated 12 hypotheses

Choose an option: Q   # Quit (progress saved)

# Resume later...
$ python hunt_menu.py vul/admin-bar
Status: Phase 2/8 completed

Choose an option: R   # Resume from Phase 3
```

## State Persistence

Context saved to: `<target>/.zerokit_context.pkl`

- ✅ Auto-saves after each phase
- ✅ Resume from any phase
- ✅ Never lose progress

## vs Original Pipeline

| Feature | `hunt_menu.py` | `hunt_pipeline.py` |
|---------|----------------|-------------------|
| Control | Phase-by-phase | Fully automated |
| Resume | ✅ | ❌ |
| UI | Interactive menu | Logs only |
| Use Case | Manual analysis | CI/CD automation |

---

**For detailed documentation**: See [walkthrough.md](file:///C:/Users/bapcorn/.gemini/antigravity/brain/4153ce08-acdb-4b20-94bd-a779bcd27db8/walkthrough.md)
