#!/usr/bin/env python3
"""Replace lsm_hook.c with a 4.14-compatible version using list_head."""

import sys

path = sys.argv[1] if len(sys.argv) > 1 else "KernelSU/kernel/hook/lsm_hook.c"

with open(path, 'r') as f:
    lines = f.readlines()

# Find key section boundaries
hook_start = None     # start of ksu_lsm_hook
decl_start = None     # #else inside ksu_lsm_hook (var decls)
impl_start = None     # #else after 6.12 block (implementation)
impl_end = None       # #endif matching that #else
unhook_start = None   # #else inside ksu_lsm_unhook
unhook_end = None     # #endif matching that

for i, line in enumerate(lines):
    stripped = line.strip()
    # Track function boundaries to find the right #else blocks
    if stripped == "int ksu_lsm_hook(struct ksu_lsm_hook *hook)":
        hook_start = i
    if hook_start is not None and decl_start is None and stripped == "#else":
        if i > hook_start and i < (impl_start or float('inf')):
            decl_start = i
    if hook_start is not None and stripped == "#else":
        if decl_start and i > decl_start:
            impl_start = i
    if impl_start is not None and stripped == "#endif":
        impl_end = i
        break

# Find unhook #else/#endif
for i, line in enumerate(lines):
    if "void ksu_lsm_unhook" in line:
        unhook_start = i
    if unhook_start is not None and line.strip() == "#else":
        if i > unhook_start:
            unhook_start_i = i
            break

for i in range(unhook_start_i, len(lines)):
    if lines[i].strip() == "#endif":
        unhook_end_i = i
        break

# Check bounds
if not all([decl_start, impl_start, impl_end, unhook_start_i, unhook_end_i]):
    print("Error: could not locate all #else/#endif blocks")
    sys.exit(1)

# Replace declarations (struct hlist_head -> struct list_head)
old_decl = lines[decl_start+1:impl_start]
for i in range(len(old_decl)):
    old_decl[i] = old_decl[i].replace("struct hlist_head *head", "struct list_head *head")
    old_decl[i] = old_decl[i].replace("struct hlist_head *head_end", "struct list_head *head_end")

# Build the 4.14-compatible implementation block
impl_4_14 = """\
    heads_addr = find_kernel_symbol_exact("security_hook_heads");
    if (!heads_addr) {
        pr_err("lsm_hook: failed to resolve security_hook_heads\\n");
        ret = -ENOENT;
        goto out_unlock;
    }
    unsigned long heads_size = sizeof(struct security_hook_heads);
    if (!kallsyms_lookup_size_offset(heads_addr, &heads_size, NULL)) {
        pr_warn("lookup head size failed");
    }

    head = (struct list_head *)heads_addr;
    struct list_head *head_end = (struct list_head *)(heads_addr + heads_size);
    pr_info("heads_addr 0x%lx head_offset 0x%lx heads_size %ld hook_offset 0x%lx\\n", (unsigned long)heads_addr,
            hook->head_offset, heads_size, hook->hook_offset);

    for (; head < head_end; head++) {
        list_for_each_entry (entry, head, list) {
            void **slot = (void **)((char *)entry + hook->hook_offset);
            void *current_origin = READ_ONCE(*slot);
            int j;
            for (j = 0; j < ksu_lsm_hook_count; j++) {
                if (ksu_lsm_hook_entries[j].hook->replacement == current_origin) {
                    current_origin = ksu_lsm_hook_entries[j].hook->original;
                    break;
                }
            }
            if (current_origin == hook->replacement) {
                ret = -EALREADY;
                goto out_unlock;
            }
            if (current_origin == target) {
                pr_info("found %s (target %s) at head offset %ld (provided %ld)\\n", hook->head_name, hook->target_name,
                        (unsigned long)head - heads_addr, hook->head_offset);
                selected_entry = entry;
                selected_slot = slot;
                selected_origin = current_origin;
                break;
            }
        }
        if (selected_entry) {
            if (hook->offset) {
                head += hook->offset;
                if (head < (struct list_head *)heads_addr || head >= head_end) {
                    pr_err("invalid offset\\n");
                    ret = -EINVAL;
                    goto out_unlock;
                }
                list_for_each_entry (entry, head, list) {
                    void **slot = (void **)((char *)entry + hook->hook_offset);
                    void *current_origin = READ_ONCE(*slot);
                    if (current_origin == hook->replacement) {
                        ret = -EALREADY;
                        goto out_unlock;
                    }
                }
                if (head->next != head) {
                    selected_entry = list_entry(head->next, struct security_hook_list, list);
                    selected_slot = (void **)((char *)selected_entry + hook->hook_offset);
                    selected_origin = *selected_slot;
                } else {
                    selected_entry = &hook->list;
                    hook->list.head = head;
                    INIT_LIST_HEAD(&hook->list.list);
                    list_add_tail(&hook->list.list, head);
                    hook->list.lsm = "ksu";
                    *(void **)((char *)selected_entry + hook->hook_offset) = hook->replacement;
                    selected_slot = (void **)&head->next;
                    selected_origin = NULL;
                }
            }
            break;
        }
    }

    if (!selected_entry) {
        pr_err("lsm_hook: target %s not found in head %s\\n", target_name, hook->head_name ?: "unknown");
        ret = -ENOENT;
        goto out_unlock;
    }

    ret = ksu_lsm_hook_track(hook);
    if (ret) {
        pr_err("lsm_hook: too many hooks to track: %d\\n", ret);
        goto out_unlock;
    }

    if (selected_origin) {
        pr_info("patch func addr\\n");
        ret = ksu_lsm_hook_patch_slot(selected_slot, hook->replacement);
    } else {
        pr_info("patch head->next\\n");
        ret = ksu_lsm_hook_patch_slot(selected_slot, &hook->list);
    }

    if (ret) {
        pr_err("lsm_hook: failed to patch %s\\n", hook->head_name ?: "unknown");
        ret = -EFAULT;
        goto out_untrack;
    }

    hook->entry = selected_entry;
    hook->original = selected_origin;
    pr_info("lsm_hook: patched %s hook slot %px from %px to %px\\n", hook->head_name ?: "unknown", selected_slot,
            selected_origin, hook->replacement);
"""

# Unhook function replacement for 4.14
unhook_4_14 = """\
    if (hook->entry == &hook->list) {
        slot = (void **)&hook->list.head->next;
        pr_info("unhook patch head->next\\n");
    } else {
        slot = (void **)((char *)hook->entry + hook->hook_offset);
        pr_info("unhook patch slot\\n");
    }
"""

# Apply patches
result = lines[:decl_start+1] + old_decl + lines[impl_start:impl_start+1]
result.append(impl_4_14)
result.append("#endif\n")
# Skip old impl to impl_end
rest = lines[impl_end+1:unhook_start_i+1]
rest.append(unhook_4_14)
rest.append("\n")
# Skip old unhook to unhook_end
rest += lines[unhook_end_i+1:]
result += rest

with open(path, 'w') as f:
    f.writelines(result)

print(f"Patched {path} for 4.14 compatibility (list_head)")
