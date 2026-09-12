# Contributing

Use synthetic artifacts only. Never commit licensed Corda binaries, customer logs, credentials or private correspondence. Optional local licensed validation belongs under ignored fixtures/private and must never be copied into image build contexts or release archives.

Run all development dependencies inside Docker. Build and tests: `docker build -t ledgerpreflight:0.1.0 .`. Run scripts/validate.sh inside the Ubuntu22.04 build container for the local release sequence, then scripts/validate-ubuntu.sh in clean Ubuntu18.04/20.04/22.04 containers. No host JDK, Gradle, Node or Python is required or permitted by this project's development workflow.

Add exact-descriptor synthetic tests for compatibility changes and adversarial cases for every parser. Vendor rules need a current docs.r3.com source and crosswalk entry. User rules must stay declarative, additive, bounded and unable to suppress built-in blockers. Do not publish an unverified vendor defect claim.
