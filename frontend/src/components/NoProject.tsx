export default function NoProject() {
  return (
    <div className="card p-8 text-center">
      <h2 className="text-lg font-semibold text-slate-100">No project selected</h2>
      <p className="mt-2 text-sm text-slate-400">
        This page loads records for the signed-in account only. Create or select a project in the header.
        Demo sample records are not shown here.
      </p>
    </div>
  );
}
