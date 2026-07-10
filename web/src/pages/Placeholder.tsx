import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";

export function Placeholder({ title, note }: { title: string; note?: string }) {
  return (
    <div>
      <h1 className="text-2xl font-semibold mb-4">{title}</h1>
      <Card>
        <CardHeader>
          <CardTitle>Coming up</CardTitle>
        </CardHeader>
        <CardBody>
          <p className="text-sm text-subtle">
            {note ?? "This section is scaffolded but not yet implemented. The backend endpoints are live; UI lands in a follow-up task."}
          </p>
        </CardBody>
      </Card>
    </div>
  );
}
