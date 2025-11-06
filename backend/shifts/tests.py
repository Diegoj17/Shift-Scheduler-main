from django.test import TestCase


class ShiftTypeDataMigrationTest(TestCase):
    """Comprueba que la migración de datos creó los tipos de turno esperados."""

    def test_shift_types_exist_with_correct_values(self):
        from shifts.models import ShiftType

        expected = {
            'Turno Mañana': {'start_time': '06:00:00', 'end_time': '11:59:00', 'color': '#4CAF50'},
            'Turno Tarde': {'start_time': '12:00:00', 'end_time': '17:59:00', 'color': '#FFC107'},
            'Turno Noche': {'start_time': '18:00:00', 'end_time': '05:59:00', 'color': '#2196F3'},
        }

        for name, attrs in expected.items():
            with self.subTest(shift_type=name):
                qs = ShiftType.objects.filter(name=name)
                self.assertTrue(qs.exists(), msg=f"El ShiftType '{name}' no existe")
                st = qs.first()
                # Comparar representaciones string de time para evitar diferencias de tipo
                self.assertEqual(str(st.start_time), attrs['start_time'])
                self.assertEqual(str(st.end_time), attrs['end_time'])
                self.assertEqual(st.color, attrs['color'])
