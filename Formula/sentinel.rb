class Sentinel < Formula
  desc "Unified DevSecOps Scanner for SAST, SCA, Secrets, IaC, and DAST"
  homepage "https://github.com/DraculaHub786/DevSecOps-Unified-Scanner"
  url "https://github.com/DraculaHub786/DevSecOps-Unified-Scanner/archive/refs/tags/v1.0.2.tar.gz"
  license "Apache-2.0"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w -X main.version=1.0.2"), "./cmd/sentinel"
  end

  test do
    assert_match "Sentinel DevSecOps Unified Scanner v1.0.2", shell_output("#{bin}/sentinel version")
    assert_match "Mode:", shell_output("#{bin}/sentinel doctor")
  end
end
