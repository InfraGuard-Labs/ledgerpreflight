package io.ledgerpreflight.integration;

import io.ledgerpreflight.cli.GuidedTvuExecution;
import io.ledgerpreflight.core.AssessmentService;
import java.nio.file.Path;

/** Isolated parent JVM used only to send actual POSIX termination signals in Docker tests. */
public final class GuidedTvuSignalHarness {
    public static void main(String[] args)throws Exception {
        var fixture=GuidedTvuFixtureFactory.create(Path.of(args[0]),"cancel",false);
        var plan=GuidedTvuExecution.inspect(fixture.options(),new AssessmentService().assess(fixture.options()),null,null,fixture.reports());
        GuidedTvuExecution.run(plan,true,60,p->{},()->false);
    }
}
