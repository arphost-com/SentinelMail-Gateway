import { Component, ErrorInfo, ReactNode } from "react";
import { Button } from "./ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "./ui/Card";

interface Props {
  children: ReactNode;
  // Used as a `key` reset signal by parent — when this changes we drop the
  // captured error so the page tries to render again (e.g. on navigation).
  resetKey?: string;
}

interface State {
  err: Error | null;
}

/**
 * Catches uncaught rendering errors in a subtree so a single bad page doesn't
 * blank the entire app. Without this React unmounts everything on a throw
 * and the user sees a blank screen with no clue what happened.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { err: null };

  static getDerivedStateFromError(err: Error): State {
    return { err };
  }

  componentDidCatch(err: Error, info: ErrorInfo) {
    // Surface to the browser console so devs / users helping debug can copy it.
    console.error("ErrorBoundary caught:", err, info.componentStack);
  }

  componentDidUpdate(prev: Props) {
    if (prev.resetKey !== this.props.resetKey && this.state.err) {
      this.setState({ err: null });
    }
  }

  render() {
    if (!this.state.err) return this.props.children;
    return (
      <div className="p-6">
        <Card>
          <CardHeader>
            <CardTitle>Something went wrong</CardTitle>
          </CardHeader>
          <CardBody>
            <p className="text-sm text-subtle mb-3">
              This screen crashed while rendering. Try reloading; if the error sticks, the
              message below is what to paste in a bug report.
            </p>
            <pre className="text-xs bg-muted p-3 rounded overflow-auto max-h-64" role="alert">
              {this.state.err.name}: {this.state.err.message}
              {this.state.err.stack && "\n\n" + this.state.err.stack}
            </pre>
            <div className="mt-3 flex gap-2">
              <Button onClick={() => this.setState({ err: null })}>Try again</Button>
              <Button variant="secondary" onClick={() => window.location.reload()}>Reload page</Button>
            </div>
          </CardBody>
        </Card>
      </div>
    );
  }
}
