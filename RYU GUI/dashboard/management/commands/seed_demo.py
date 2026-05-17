"""Seed the database with realistic demo data so the dashboard isn't empty.

Usage:  python manage.py seed_demo
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
import random

from dashboard.models import Event, Switch, Host, Threat, ControllerStatus


class Command(BaseCommand):
    help = "Populate database with demo data for the dashboard."

    def handle(self, *args, **opts):
        # ----- Controller status -----
        cs = ControllerStatus.current()
        cs.is_online = True
        cs.version = "Ryu 4.34"
        cs.uptime_seconds = 12345
        cs.save()

        # ----- Switches -----
        Switch.objects.all().delete()
        switches = []
        for i in range(8):
            switches.append(Switch.objects.create(
                dpid=f"0000000000000{i+1:03d}",
                name=f"OVS-{i+1:02d}",
                ip_address=f"10.0.0.{i+1}",
                is_active=True, n_ports=random.randint(4, 24),
                n_flows=random.randint(8, 40),
            ))

        # ----- Hosts -----
        Host.objects.all().delete()
        for i in range(18):
            Host.objects.create(
                mac=":".join(f"{random.randint(0,255):02x}" for _ in range(6)),
                ip_address=f"192.168.1.{i+10}",
                switch=random.choice(switches),
                port_no=random.randint(1, 24),
                is_iot=(i % 3 == 0),
            )

        # ----- Events -----
        Event.objects.all().delete()
        types = list(Event.EventType.choices)
        sevs = list(Event.Severity.choices)
        now = timezone.now()
        for i in range(50):
            et = random.choice(types)
            sev = random.choice(sevs)
            Event.objects.create(
                event_type=et[0],
                severity=sev[0],
                source=f"OVS-{random.randint(1,8):02d}",
                description=f"{et[1]} on port {random.randint(1,24)}",
            )

        # ----- Threats -----
        Threat.objects.all().delete()
        attacks = ["ddos", "mirai", "scan", "brute_force", "exfil"]
        for i in range(12):
            Threat.objects.create(
                src_ip=f"192.168.1.{random.randint(2,254)}",
                dst_ip=f"10.0.0.{random.randint(2,254)}",
                threat_type=random.choice(attacks),
                confidence=round(random.uniform(0.70, 0.99), 3),
                status=random.choice([
                    Threat.Status.DETECTED, Threat.Status.MITIGATED,
                ]),
            )

        self.stdout.write(self.style.SUCCESS(
            f"Seeded: {Switch.objects.count()} switches, "
            f"{Host.objects.count()} hosts, "
            f"{Event.objects.count()} events, "
            f"{Threat.objects.count()} threats."
        ))
