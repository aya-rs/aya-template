CARGO = cargo
RUNNER = sudo -E

RUN_ARGS = # User provided args could go here, or be specified at cmd line

DEBUG   = target/debug/{{project-name}}
RELEASE = target/release/{{project-name}}

DEBUG_BPF   = target/bpfel-unknown-none/debug/{{project-name}}
RELEASE_BPF = target/bpfel-unknown-none/release/{{project-name}}

USER_SRCS   =  $(wildcard {{project-name}}-common/**/*)
COMMON_SRCS =  $(wildcard {{project-name}}/**/*)
BPF_SRCS    =  $(wildcard {{project-name}}-ebpf/**/*)

.PHONY: build
build: $(DEBUG)

.PHONY: run
run: $(DEBUG)
	$(RUNNER) ./$(DEBUG) --path $(DEBUG_BPF) $(RUN_ARGS)

.PHONY: build-release
build-release: $(RELEASE)

.PHONY: run-release
run-release: $(RELEASE)
	$(RUNNER) ./$(RELEASE) --path $(RELEASE_BPF) $(RUN_ARGS)

.PHONY: clean
clean:
	$(CARGO) clean

$(DEBUG): $(DEBUG_BPF) $(USER_SRCS) $(COMMON_SRCS)
	$(CARGO) build

$(DEBUG_BPF): $(BPF_SRCS) $(COMMON_SRCS)
	$(CARGO) xtask build-ebpf

$(RELEASE): $(RELEASE_BPF) $(USER_SRCS) $(COMMON_SRCS)
	$(CARGO) build --release

$(RELEASE_BPF): $(BPF_SRCS) $(COMMON_SRCS)
	$(CARGO) xtask build-ebpf --release
