# Dependency Upgrade Notes

- When upgrading XTLS/Xray-core (`github.com/xtls/xray-core`), revert commit
  `0884efb` (`fix: default REALITY minimum client version to 1.0.0`). It is a
  temporary compatibility workaround for Xray-core v26.7.28. Review the new
  core's REALITY client requirements and rerun the relevant tests after reverting.
