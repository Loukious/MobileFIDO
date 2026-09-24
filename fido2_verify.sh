#!/system/bin/sh
#
# fido2_verify.sh -- read-only verification, Android side.
#
# Touches nothing. Safe to run at any time, including before provisioning and
# after a rollback. Produces the on-device half of the Milestone 1 evidence:
# the HID interface parameters, the actual /dev node, its SELinux context and
# permissions, and proof that hid.0/hid.1 are untouched.

. "$(dirname "$0")/fido2_env.sh"

echo "=================================================================="
echo "FIDO2 CTAP HID gadget -- verification"
echo "=================================================================="

echo
echo "--- composite gadget identity ---"
echo "  UDC          : $(cat "$CFG_ROOT/UDC" 2>/dev/null)"
echo "  idVendor     : $(cat "$CFG_ROOT/idVendor" 2>/dev/null)"
echo "  idProduct    : $(cat "$CFG_ROOT/idProduct" 2>/dev/null)"
echo "  bcdDevice    : $(cat "$CFG_ROOT/bcdDevice" 2>/dev/null)"
echo "  bcdUSB       : $(cat "$CFG_ROOT/bcdUSB" 2>/dev/null)"
echo "  manufacturer : $(cat "$STR_DIR/manufacturer" 2>/dev/null)"
echo "  product      : $(cat "$STR_DIR/product" 2>/dev/null)"
echo "  serialnumber : $(cat "$STR_DIR/serialnumber" 2>/dev/null)"
echo "  os_desc      : use=$(cat "$CFG_ROOT/os_desc/use" 2>/dev/null) vendor_code=$(cat "$CFG_ROOT/os_desc/b_vendor_code" 2>/dev/null) sign=$(cat "$CFG_ROOT/os_desc/qw_sign" 2>/dev/null)"

echo
echo "--- configs/b.1 links (interface order) ---"
_i=0
for _l in "$CFG_DIR"/*; do
    [ -L "$_l" ] || continue
    echo "  $(basename "$_l") -> $(basename "$(readlink "$_l")")"
    _i=$((_i + 1))
done
echo "  ($_i functions linked)"

echo
echo "--- FIDO function instance: $FIDO_FUNC_NAME ---"
if [ -d "$FIDO_FUNC_DIR" ]; then
    echo "  protocol        : $(cat "$FIDO_FUNC_DIR/protocol" 2>/dev/null)"
    echo "  subclass        : $(cat "$FIDO_FUNC_DIR/subclass" 2>/dev/null)"
    echo "  report_length   : $(cat "$FIDO_FUNC_DIR/report_length" 2>/dev/null)"
    echo "  no_out_endpoint : $(cat "$FIDO_FUNC_DIR/no_out_endpoint" 2>/dev/null)"
    echo "  dev (major:min) : $(hid_func_dev "$FIDO_FUNC_DIR")"
    echo -n "  descriptor      : "
    $BUSYBOX od -An -tx1 -v -N "$FIDO_DESC_LEN" "$FIDO_FUNC_DIR/report_desc" 2>/dev/null | tr -s ' ' | tr '\n' ' '
    echo
    echo -n "  descriptor len  : "
    $BUSYBOX od -An -tx1 -v -N "$FIDO_DESC_LEN" "$FIDO_FUNC_DIR/report_desc" 2>/dev/null | tr -s ' ' '\n' | grep -c .
    echo -n "  descriptor sha  : "
    $BUSYBOX head -c "$FIDO_DESC_LEN" "$FIDO_FUNC_DIR/report_desc" 2>/dev/null | $BUSYBOX sha256sum 2>/dev/null | $BUSYBOX cut -c1-64
    echo -n "  matches CTAP    : "
    if hid_desc_matches "$FIDO_FUNC_DIR"; then echo "YES"; else echo "NO"; fi
    echo -n "  linked as       : "
    _ln=$(link_for_func "$FIDO_FUNC_NAME")
    if [ -n "$_ln" ]; then echo "$_ln"; else echo "(NOT LINKED)"; fi
else
    echo "  (function instance does not exist)"
fi

echo
echo "--- /dev node (requirement 9: derived from the dev attribute, not assumed) ---"
if [ -d "$FIDO_FUNC_DIR" ]; then
    _node=$(hid_func_node "$FIDO_FUNC_DIR")
    if [ -n "$_node" ]; then
        _hm=$(hid_func_dev "$FIDO_FUNC_DIR")
        echo "  dev attribute          : $_hm"
        echo "  node implied by minor  : /dev/hidg${_hm#*:}"
        echo "  resolved node          : $_node"
        echo "  ls -lZ                 :"
        ls -lZ "$_node" 2>/dev/null | sed 's/^/    /'
        # `ls -Z` alone prints "<context> <name>", so field 5 only exists in
        # the long form. Parse the same `ls -lZ` line we just printed.
        _ctx=$(ls -lZ "$_node" 2>/dev/null | $BUSYBOX awk '{print $5}')
        echo "  SELinux context        : ${_ctx:-(unparsed; see the ls -lZ line above)}"
        if [ -r "$_node" ] && [ -w "$_node" ]; then
            echo "  read/write (as root)   : YES"
        else
            echo "  read/write (as root)   : NO"
        fi
    else
        echo "  (no matching /dev node present)"
        echo "  /dev/hidg* currently   : $(ls /dev/hidg* 2>/dev/null | tr '\n' ' ')"
    fi
fi

echo
echo "--- all /dev/hidg* nodes ---"
_hidg_any=0
for _n in /dev/hidg*; do
    [ -c "$_n" ] || continue
    _hidg_any=1
    ls -lZ "$_n" 2>/dev/null | sed 's/^/  /'
done
# Only hidg0/hidg1 are linked when USB Arsenal is driving the keyboard/mouse;
# while only the CTAP function is linked, hidg2 is the sole node and that is
# correct, not a fault.
[ "$_hidg_any" = "1" ] || echo "  (no /dev/hidg* node: no HID function is currently bound)"

echo
echo "--- NetHunter HID functions (requirement 4: must be untouched) ---"
for _h in hid.0 hid.1; do
    if [ -d "$FUNCS_DIR/$_h" ]; then
        echo "  $_h: protocol=$(cat "$FUNCS_DIR/$_h/protocol" 2>/dev/null) subclass=$(cat "$FUNCS_DIR/$_h/subclass" 2>/dev/null) report_length=$(cat "$FUNCS_DIR/$_h/report_length" 2>/dev/null) dev=$(cat "$FUNCS_DIR/$_h/dev" 2>/dev/null)"
        echo -n "        sha256: "
        $BUSYBOX head -c 4096 "$FUNCS_DIR/$_h/report_desc" 2>/dev/null | $BUSYBOX sha256sum 2>/dev/null | $BUSYBOX cut -c1-64
    else
        echo "  $_h: MISSING"
    fi
done

if [ -f "$ORIGINAL_ENV" ]; then
    . "$ORIGINAL_ENV"
    echo
    echo "--- comparison against pre-change snapshot ---"
    _h0=$($BUSYBOX head -c 4096 "$FUNCS_DIR/hid.0/report_desc" 2>/dev/null | $BUSYBOX sha256sum 2>/dev/null | $BUSYBOX cut -c1-64)
    _h1=$($BUSYBOX head -c 4096 "$FUNCS_DIR/hid.1/report_desc" 2>/dev/null | $BUSYBOX sha256sum 2>/dev/null | $BUSYBOX cut -c1-64)
    [ "$_h0" = "$ORI_HID0_DESC_SHA" ] && echo "  hid.0 descriptor : unchanged" || echo "  hid.0 descriptor : CHANGED"
    [ "$_h1" = "$ORI_HID1_DESC_SHA" ] && echo "  hid.1 descriptor : unchanged" || echo "  hid.1 descriptor : CHANGED"
    echo "  original identity: VID=$ORI_VID PID=$ORI_PID bcdDevice=$ORI_BCDDEVICE"
    echo "  original links   : $ORI_LINKS"
else
    echo
    echo "--- no snapshot present (nothing has been provisioned yet, or it was rolled back) ---"
fi

echo
echo "--- adb path ---"
echo "  adbd pid     : $(pidof adbd 2>/dev/null)"
echo "  ffs.ready    : $(getprop sys.usb.ffs.ready)"
echo "  ffs.adb link : $(link_for_func ffs.adb)"
echo "  sys.usb.config: $(getprop sys.usb.config)"

echo
echo "--- watchdog ---"
if [ -f "$WATCHDOG_PID" ] && kill -0 "$(cat "$WATCHDOG_PID" 2>/dev/null)" 2>/dev/null; then
    echo "  RUNNING (pid $(cat "$WATCHDOG_PID")) -- change not yet confirmed, will auto-revert"
elif [ -f "$KEEP_FLAG" ]; then
    echo "  stood down; change CONFIRMED ($(cat "$KEEP_FLAG"))"
elif [ -f "$REVERTED_FLAG" ]; then
    echo "  rollback has been performed"
else
    echo "  not running, not confirmed, nothing to revert"
fi
echo
