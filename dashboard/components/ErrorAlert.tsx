/**
 * Error alert — displays a clean, user-facing error message.
 * Never renders stack traces or raw backend internals.
 */

export default function ErrorAlert({ message }: { message: string }) {
  return (
    <div className="alert alert-error" role="alert">
      {message}
    </div>
  );
}
