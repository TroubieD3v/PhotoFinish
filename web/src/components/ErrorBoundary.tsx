import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  /** Changing the key clears a caught error (a new screen gets a fresh start). */
  resetKey: string;
  children: ReactNode;
}

interface State {
  error: Error | null;
  key: string;
}

/** Shows a rendering error in place of the screen instead of a blank page. */
export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null, key: this.props.resetKey };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  static getDerivedStateFromProps(props: Props, state: State): Partial<State> | null {
    return props.resetKey !== state.key ? { error: null, key: props.resetKey } : null;
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    console.warn("PhotoFinish UI error", error, info.componentStack);
  }

  override render() {
    if (this.state.error) {
      return (
        <div className="screen">
          <div className="crash" role="alert">
            <h1>This view failed to render</h1>
            <p className="muted">{this.state.error.message}</p>
            <button type="button" className="btn" onClick={() => this.setState({ error: null })}>
              Try again
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
