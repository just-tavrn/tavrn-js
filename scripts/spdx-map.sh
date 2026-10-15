# SPDX-License-Identifier: Apache-2.0
#
# The license map of scripts/check-spdx.sh (sourced by it): the files it checks and the license of each path, first
# match wins. Keep it in sync with LICENSE.md: @tavrn/e2ee is MPL-2.0, everything else Apache-2.0; the
# generated client code is not checked.
# shellcheck shell=bash disable=SC2034 # spdx_files is read by check-spdx.sh

spdx_files=('*.rs' '*.ts' '*.tsx' '*.mjs' '*.js' '*.sh')

license_for() {
  case "$1" in
    sdk/src/generated/* | */node_modules/* | node_modules/* | protocol/*) echo skip ;;
    e2ee/*) echo MPL-2.0 ;;
    sdk/* | bot/* | scripts/*) echo Apache-2.0 ;;
    *) echo unmapped ;;
  esac
}
