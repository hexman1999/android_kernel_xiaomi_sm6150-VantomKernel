#!/bin/bash
# Patches KOWX712/KernelSU for Linux 4.14 compatibility
# Called from CI workflow after cloning KernelSU

set -e

KSU_DIR="${1:-KernelSU}"

echo "::group::Patching KernelSU for 4.14"

# 1. syscall_hook.h: add ARM64 syscall_fn_t typedef
echo "-- Patching syscall_hook.h for ARM64..."
HOOK_FILE="$KSU_DIR/kernel/hook/syscall_hook.h"
python3 -c "
with open('$HOOK_FILE', 'r') as f:
    content = f.read()
old = '#endif\n\nextern syscall_fn_t'
new = '#endif\n#if defined(__aarch64__)\ntypedef long (*syscall_fn_t)(const struct pt_regs *);\n#endif\n\nextern syscall_fn_t'
content = content.replace(old, new, 1)
with open('$HOOK_FILE', 'w') as f:
    f.write(content)
"

# 2. sucompat.c: linux/pgtable.h was added in 4.15, use asm/pgtable.h on 4.14
echo "-- Patching sucompat.c header for 4.14..."
SUCOMPAT_FILE="$KSU_DIR/kernel/feature/sucompat.c"
sed -i 's|#include <linux/pgtable.h>|#include <asm/pgtable.h>|' "$SUCOMPAT_FILE"

# 3. Replace strncpy_from_user_nofault (added in 5.8) with strncpy_from_user
echo "-- Patching strncpy_from_user_nofault -> strncpy_from_user..."
for f in \
    "$KSU_DIR/kernel/feature/sucompat.c" \
    "$KSU_DIR/kernel/sulog/event.c" \
    "$KSU_DIR/kernel/runtime/ksud_integration.c"; do
    sed -i 's/strncpy_from_user_nofault/strncpy_from_user/g' "$f"
done

# 4. Replace ksys_close (added in 4.19) with sys_close in util.h
echo "-- Patching ksys_close -> sys_close for 4.14..."
UTIL_FILE="$KSU_DIR/kernel/include/util.h"
sed -i 's/#define ksu_close_fd ksys_close/#define ksu_close_fd sys_close/' "$UTIL_FILE"

# 5. init.c: comment out MODULE_IMPORT_NS (requires 5.3+)
echo "-- Patching init.c for MODULE_IMPORT_NS..."
INIT_FILE="$KSU_DIR/kernel/core/init.c"
python3 -c "
with open('$INIT_FILE', 'r') as f:
    content = f.read()
content = content.replace(
    'MODULE_IMPORT_NS(\"VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver\");',
    '// MODULE_IMPORT_NS(\"VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver\");'
)
content = content.replace(
    'MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);',
    '// MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);'
)
with open('$INIT_FILE', 'w') as f:
    f.write(content)
"

echo "::endgroup::"
