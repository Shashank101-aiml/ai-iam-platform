"""
Database Seed Script for AI-IAM Platform.
Populates an initial production-ready dataset including:
- Default Organization ('Acme Corp AI')
- Superuser Operator account ('admin@acmecorp.ai')
- ReBAC Permissions & Roles ('Super Admin', 'Security Monitor', 'Data Worker')
- Multi-Tier Agent Hierarchy ('Core Supervisor Agent' -> 'Analytics Sub-Agent')
"""

import asyncio
import uuid
import bcrypt
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import AsyncSessionLocal, engine
from app.db.database import init_db
from app.models.organization import Organization
from app.models.user import User
from app.models.permission import Permission
from app.models.role import Role
from app.models.agent import Agent
from app.core.constants import AgentStatus
from app.repositories.role_repo import role_repo


async def seed() -> None:
    print("Initializing database schema...")
    await init_db()

    async with AsyncSessionLocal() as db:
        # Check if already seeded
        existing_org = await db.execute(select(Organization).where(Organization.slug == "acmecorp-ai"))
        if existing_org.scalar_one_or_none():
            print("Database already seeded (`acmecorp-ai` found). Exiting seed script.")
            return

        print("Creating default organization: Acme Corp AI...")
        org = Organization(
            id=str(uuid.uuid4()),
            name="Acme Corp AI",
            slug="acmecorp-ai",
            is_active=True,
            metadata_="Primary corporate AI organization boundary",
        )
        db.add(org)
        await db.flush()

        print("Creating superuser operator account...")
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(b"AdminPass123!", salt).decode()
        admin_user = User(
            id=str(uuid.uuid4()),
            org_id=org.id,
            email="admin@acmecorp.ai",
            hashed_password=hashed,
            is_active=True,
            is_superuser=True,
        )
        db.add(admin_user)
        await db.flush()

        print("Creating core ReBAC permissions & roles...")
        scopes = [
            ("audit:read", "Read tamper-evident audit logs"),
            ("tool:execute", "Execute proxy MCP tools"),
            ("threat:mitigate", "Trigger automated security mitigations"),
            ("agent:delegate", "Issue multi-hop delegation grants"),
        ]
        for name, desc in scopes:
            perm = Permission(
                id=str(uuid.uuid4()),
                org_id=org.id,
                name=name,
                description=desc,
                resource_type="system",
                action=name.split(":")[1],
            )
            db.add(perm)

        role_admin = Role(
            id=str(uuid.uuid4()),
            org_id=org.id,
            name="Super Admin Role",
            description="Full unrestricted platform governance",
            scopes=["audit:read", "tool:execute", "threat:mitigate", "agent:delegate"],
        )
        role_worker = Role(
            id=str(uuid.uuid4()),
            org_id=org.id,
            name="Worker Role",
            description="Standard operational agent role",
            scopes=["tool:execute"],
        )
        db.add_all([role_admin, role_worker])
        await db.flush()

        print("Creating multi-tier AI agent hierarchy...")
        supervisor = Agent(
            id=str(uuid.uuid4()),
            org_id=org.id,
            name="Core Supervisor Agent",
            description="Top-level autonomous governance orchestrator",
            status=AgentStatus.ACTIVE,
            spiffe_id=f"spiffe://ai-iam.internal/ns/{org.id}/sa/supervisor",
            max_delegation_depth=5,
            is_ephemeral=False,
            allowed_scopes=["audit:read", "tool:execute", "threat:mitigate", "agent:delegate"],
            mcp_bindings=[{"server": "security-mcp", "url": "http://security-mcp:8080"}],
        )
        db.add(supervisor)
        await db.flush()

        sub_agent = Agent(
            id=str(uuid.uuid4()),
            org_id=org.id,
            name="Analytics Sub-Agent",
            description="Specialized data query worker",
            status=AgentStatus.ACTIVE,
            spiffe_id=f"spiffe://ai-iam.internal/ns/{org.id}/sa/analytics-sub",
            parent_agent_id=supervisor.id,
            max_delegation_depth=2,
            is_ephemeral=False,
            allowed_scopes=["tool:execute"],
            mcp_bindings=[{"server": "data-mcp", "url": "http://data-mcp:8080"}],
        )
        db.add(sub_agent)
        await db.flush()

        # Assign roles to agents
        await role_repo.assign_to_agent(db, supervisor.id, role_admin.id)
        await role_repo.assign_to_agent(db, sub_agent.id, role_worker.id)

        await db.commit()
        print("\n✅ Database seed completed successfully!")
        print(f"   - Organization: Acme Corp AI (ID: {org.id})")
        print(f"   - Operator Login: admin@acmecorp.ai / AdminPass123!")
        print(f"   - Supervisor Agent: {supervisor.name} (SPIFFE: {supervisor.spiffe_id})")
        print(f"   - Child Sub-Agent: {sub_agent.name} (SPIFFE: {sub_agent.spiffe_id})")


if __name__ == "__main__":
    asyncio.run(seed())
